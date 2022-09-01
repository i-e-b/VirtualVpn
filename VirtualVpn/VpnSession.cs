using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using SkinnyJson;
using VirtualVpn.Crypto;
using VirtualVpn.Enums;
using VirtualVpn.EspProtocol;
using VirtualVpn.EspProtocol.Payloads;
using VirtualVpn.EspProtocol.Payloads.PayloadSubunits;
using VirtualVpn.Helpers;
using VirtualVpn.InternetProtocol;

namespace VirtualVpn;

/// <summary>
/// Negotiates and handles a single VPN session between self and one peer.
/// Most of this is covered by RFC 5996: https://datatracker.ietf.org/doc/html/rfc5996
/// </summary>
public class VpnSession
{
    //## State machine vars ##//
    public SessionState State
    {
        get => _state;
        private set
        {
            Log.Info($"    Session entered state {value.ToString()}");
            _state = value;
        }
    }

    private long _peerMsgId;
    private byte[]? _initMessage;
    private byte[]? _lastSentMessageBytes;
    private byte[]? _previousRequestRawData;
    
    private byte[]? _peerNonce;
    private byte[]? _skD;

    private readonly Dictionary<uint, ChildSa> _thisSessionChildren = new();
    private SessionState _state;
    private IPEndPoint? _lastContact;

    //## Algorithmic selections (negotiated with peer) ##//

    private IkeCrypto? _myCrypto;
    private IkeCrypto? _peerCrypto;

    //## Locked for session ##//

    private ulong _peerSpi;
    
    private readonly IUdpServer _server; // note: should increment _seqOut when sending
    private readonly ISessionHost _sessionHost;
    private readonly bool _weAreInitiator;
    private readonly ulong _localSpi;
    private readonly byte[] _localNonce;
    private BCDiffieHellman? _keyExchange;
    private Proposal? _lastSaProposal;

    /// <summary>
    /// Start a new session object
    /// </summary>
    /// <param name="gateway">Address of remote peer</param>
    /// <param name="server">Local send/receive socket</param>
    /// <param name="sessionHost">Host that manages multiple sessions</param>
    /// <param name="weAreInitiator">True if local is going to start the connection,
    /// false if this session is started in response to an outside request.</param>
    /// <param name="peerSpi">SPI value of remote peer, or zero if we are the initiator.</param>
    public VpnSession(IpV4Address gateway, IUdpServer server, ISessionHost sessionHost, bool weAreInitiator, ulong peerSpi)
    {
        // pvpn/server.py:208
        Gateway = gateway;
        _server = server;
        _sessionHost = sessionHost;
        _weAreInitiator = weAreInitiator;
        _peerSpi = peerSpi;
        _localSpi = Bit.RandomSpi();
        _localNonce = Bit.RandomNonce();
        State = SessionState.INITIAL;
        _peerMsgId = 0;
        
        LastTouchTimer = new Stopwatch();
        LastTouchTimer.Start();
    }

    public Stopwatch LastTouchTimer { get; private set; }
    public IpV4Address Gateway { get; set; }
    public ulong LocalSpi => _localSpi;
    public bool WeStarted => _weAreInitiator;

    /// <summary>
    /// Drive timed events
    /// <p></p>
    /// This method should be called periodically, usually by <see cref="VpnServer.EventPumpLoop"/>
    /// </summary>
    public void EventPump()
    {
        // We don't send keep-alive messages for any active but not established sessions where we are the initiator
        // If a session takes too long to establish, we let it die.
        // The EventPump() on each child is responsible for sending keep-alive messages if it is the initiator.
        // The VpnServer instance fires child session event pump separately from this one.

        if (State == SessionState.ESTABLISHED)
        {
            if (LastTouchTimer.Elapsed < Settings.EspTimeout) return;
            // TODO: fire a DELETE message, but don't wait for reply
            
            Log.Critical("Session timed-out after establishment. Are keep-alive messages not arriving?");
            foreach (var child in _thisSessionChildren)
            {
                _sessionHost.RemoveChildSession(child.Key);
            }

            _sessionHost.RemoveSession(_localSpi);
        }
        else
        {
            if (LastTouchTimer.Elapsed < Settings.IkeTimeout) return;
            // TODO: fire a DELETE message, but don't wait for reply
            
            Log.Critical($"Session timed-out during negotiation (state={State.ToString()}). The session will be abandoned.");
            _sessionHost.RemoveSession(_localSpi);
        }
    }

    // pvpn/server.py:253
    private byte[] BuildResponse(ExchangeType exchange, bool sendZeroHeader, IkeCrypto? crypto, params MessagePayload[] payloads)
    {
        return _weAreInitiator
            ? BuildSerialMessage(exchange, MessageFlag.Initiator | MessageFlag.Response, false, sendZeroHeader, crypto, _localSpi, _peerSpi, _peerMsgId, payloads)
            : BuildSerialMessage(exchange, MessageFlag.Response, false, sendZeroHeader, crypto, _peerSpi, _localSpi, _peerMsgId, payloads);
    }

    public static byte[] BuildSerialMessage(ExchangeType exchange, MessageFlag flags, bool useAlternateChecksum, bool sendZeroHeader, IkeCrypto? crypto,
        ulong initiatorSpi, ulong responderSpi, long msgId, params MessagePayload[] payloads)
    {
        // pvpn/server.py:253
        var resp = new IkeMessage
        {
            Exchange = exchange,
            SpiI = initiatorSpi,
            SpiR = responderSpi,
            MessageFlag = flags,
            MessageId = (uint)msgId,
            Version = IkeVersion.IkeV2,
        };
        resp.Payloads.AddRange(payloads);

        Log.Debug("        payloads outgoing:", () => resp.DescribeAllPayloads());

        return resp.ToBytes(useAlternateChecksum, sendZeroHeader, crypto); // will wrap payloads in PayloadSK if we have crypto
    }

    /// <summary>
    /// Handle an incoming key exchange message
    /// </summary>
    public void HandleIke(IkeMessage request, IPEndPoint sender, bool sendZeroHeader)
    {
        try
        {
            Log.Info($"    Incoming IKE message {request.Exchange.ToString()} {request.MessageId}");
            HandleIkeInternal(request, sender, sendZeroHeader);

            _previousRequestRawData = request.RawData; // needed to do PSK auth
        }
        catch (Exception ex)
        {
            Log.Error("Failed to handle IKE message", ex);
        }
    }

    private void HandleIkeInternal(IkeMessage request, IPEndPoint sender, bool sendZeroHeader)
    {
        // pvpn/server.py:260
        LastTouchTimer.Restart();

        // Update our records if the remote has provided an SPI
        if (_weAreInitiator && _peerSpi == 0 && request.SpiR != 0) { _peerSpi = request.SpiR; }

        // Check for peer requesting a repeat of last message
        if (request.MessageId == _peerMsgId - 1)
        {
            if (_lastSentMessageBytes is null)
            {
                Log.Warn("    Asked to repeat a message we didn't send? This session has faulted");
                ReplyNotAcceptable(sender, sendZeroHeader);
                return;
            }

            Log.Info("    Asked to repeat a message we sent. Directly re-sending.");
            _server.SendRaw(_lastSentMessageBytes, sender); // don't add zero pad again?
            return;
        }

        // make sure we're in sequence
        if (request.MessageId != _peerMsgId)
        {
            if (request.MessageId > _peerMsgId)
            {
                _peerMsgId = request.MessageId;
                Log.Warn($"Request is ahead of our sequence. Expected {_peerMsgId}, but got {request.MessageId}. Will advance and continue");
            }
            else
            {
                Log.Warn($"Request is out of sequence. Expected {_peerMsgId}, but got {request.MessageId}. Not responding");
                return;
            }
        }

        // We should have crypto now, as long as we're out of IKE_SA_INIT phase
        request.ReadPayloadChain(_peerCrypto); // pvpn/server.py:266

        RouteMessageBasedOnTypeAndState(request, sender, sendZeroHeader);
    }

    private void RouteMessageBasedOnTypeAndState(IkeMessage request, IPEndPoint sender, bool sendZeroHeader)
    {
        switch (request.Exchange)
        {
            case ExchangeType.IKE_SA_INIT: // pvpn/server.py:268
                switch (State)
                {
                    case SessionState.INITIAL:
                        Log.Info("IKE_SA_INIT received, we are responder");
                        HandleSaInit(request, sender, sendZeroHeader);
                        break;
                    case SessionState.IKE_INIT_SENT:
                        Log.Info("IKE_SA_INIT received, we are initiator");
                        Log.Warn("We should now check the message is acceptable; and if so, send the first IKE_AUTH message");
                        HandleSaConfirm(request, sender, sendZeroHeader);
                        break;
                    default:
                        throw new Exception($"Received {nameof(ExchangeType.IKE_SA_INIT)}, so expected to be in state {nameof(SessionState.INITIAL)} or {nameof(SessionState.SA_SENT)}, but was in {State.ToString()}");
                }

                _peerMsgId++;
                break;

            case ExchangeType.IKE_AUTH: // pvpn/server.py:287
                switch (State)
                {
                    case SessionState.SA_SENT:
                    {
                        Log.Info("IKE_AUTH received, we are responder");
                        HandleAuth(request, sender, sendZeroHeader);
                        _peerMsgId++;
                        break;
                    }
                    case SessionState.AUTH_SENT:
                    {
                        Log.Info("IKE_AUTH received, we are initiator");
                        HandleAuthConfirm(request, sender, sendZeroHeader);
                        break;
                    }
                    case SessionState.ESTABLISHED:
                    {
                        Log.Critical("IKE_AUTH received for established connection. We might have failed a DPD check, or not sent keep-alive messages?");
                        // TODO: need to be able to re-establish a connection we thought was up.
                        break;
                    }
                    default:
                        throw new Exception($"Received {nameof(ExchangeType.IKE_AUTH)}, so expected to be in state {nameof(SessionState.SA_SENT)} or {nameof(SessionState.AUTH_SENT)}, but was in {State.ToString()}");
                }

                break;

            case ExchangeType.INFORMATIONAL: // pvpn/server.py:315
                AssertState(SessionState.ESTABLISHED, request);
                Log.Info("INFORMATIONAL received");
                HandleInformational(request, sender, sendZeroHeader);
                _peerMsgId++;
                break;

            case ExchangeType.CREATE_CHILD_SA: // pvpn/server.py:340
                AssertState(SessionState.ESTABLISHED, request);
                // TODO: Handle this -- for us as initiator, and for re-heat
                Log.Critical("CREATE_CHILD_SA received");
                break;


            default:
                throw new Exception($"Unexpected request: {request.Exchange.ToString()}");
        }
    }

    /// <summary>
    /// Handle a new IKE_AUTH during established state.
    /// <p></p>
    /// This is for signalling changes 
    /// https://datatracker.ietf.org/doc/html/rfc4555
    /// </summary>
    /// <param name="request"></param>
    /// <param name="sender"></param>
    /// <param name="sendZeroHeader"></param>
    private void HandleMobIke(IkeMessage request, IPEndPoint sender, bool sendZeroHeader)
    {
        // IEB: Continue here. Probably need to send a correctly formed reply
        Log.Debug("        HandleMobIke():: payloads incoming:", request.DescribeAllPayloads);
        Log.Debug($"        sender={sender.Address}:{sender.Port}, zero pad={sendZeroHeader}");
        
        // https://datatracker.ietf.org/doc/html/rfc4555#page-7
        /*
   (Initiator gets information from lower layers that its attachment
   point and address have changed.)

   3) (IP_I2:4500 -> IP_R1:4500)
      HDR, SK { N(UPDATE_SA_ADDRESSES),
                N(NAT_DETECTION_SOURCE_IP),
                N(NAT_DETECTION_DESTINATION_IP) }  -->

                            <-- (IP_R1:4500 -> IP_I2:4500)
                                HDR, SK { N(NAT_DETECTION_SOURCE_IP),
                                     N(NAT_DETECTION_DESTINATION_IP) }

   (Responder verifies that the initiator has given it a correct IP
   address.)
         */
    }

    /// <summary>
    /// Send a message to peer with DELETE payload.
    /// This <i>should</i> cause the session to close in a faulted state.
    /// </summary>
    private void ReplyNotAcceptable(IPEndPoint sender, bool sendZeroHeader)
    {
        var reKeyMessage = BuildSerialMessage(ExchangeType.IKE_SA_INIT, MessageFlag.Initiator, false, sendZeroHeader, null, _localSpi, _peerSpi, _peerMsgId,
            new PayloadDelete(IkeProtocolType.IKE, Array.Empty<byte[]>())
        );

        State = SessionState.DELETED;
        Send(to: sender, reKeyMessage);
    }


    private void HandleInformational(IkeMessage request, IPEndPoint sender, bool sendZeroHeader)
    {
        // pvpn/server.py:315
        Log.Debug("        HandleInformational():: payloads incoming:", request.DescribeAllPayloads);

        // Check for any sessions the other side wants to remove
        var deletePayload = request.GetPayload<PayloadDelete>();

        if (deletePayload is null)
        {
            Log.Debug("No delete payloads found in Informational packet. Will reply, but nothing else");
            Log.Trace($"Found payloads: {string.Join(", ", request.Payloads.Select(p => p.Type.ToString()))};");
            
            var mobIkeFlag = request.GetPayload<PayloadNotify>(pl => pl.NotificationType == NotifyId.UPDATE_SA_ADDRESSES);
            if (mobIkeFlag is not null)
            {
                Log.Info("Received MOB-IKE update.");
                HandleMobIke(request, sender, sendZeroHeader);
                return;
            }

            // Nothing to do, but we must reply
            Send(to: sender, message: BuildResponse(ExchangeType.INFORMATIONAL, sendZeroHeader, _myCrypto));
            return;
        }

        if (deletePayload.ProtocolType == IkeProtocolType.IKE) // pvpn/server.py:321
        {
            // This session should be removed?
            State = SessionState.DELETED;
            _sessionHost.RemoveSession(_localSpi);

            Log.Info($"    Removing entire session {_localSpi:x16}");
            foreach (var childSa in _thisSessionChildren)
            {
                _sessionHost.RemoveChildSession(childSa.Value.SpiIn);
            }

            _thisSessionChildren.Clear();
            Send(to: sender, message: BuildResponse(ExchangeType.INFORMATIONAL, sendZeroHeader, _myCrypto, deletePayload));
            return;
        }

        if (deletePayload.SpiList.Count < 1)
        {
            Log.Warn("    Received an empty delete list");
            Send(to: sender, message: BuildResponse(ExchangeType.INFORMATIONAL, sendZeroHeader, _myCrypto, deletePayload));
            return;
        }

        Log.Debug("Received request to delete specific sessions");
        // Specific old sessions should be removed
        // pvpn/server.py:328
        var matches = new List<byte[]>(); // spi that have been removed
        foreach (var deadSpi in deletePayload.SpiList)
        {
            var removed = TryRemoveChild(deadSpi);
            Log.Debug($"Asked to remove '{deadSpi}' - {(removed ? "found" : "not found")}");
            if (removed) matches.Add(deadSpi);
        }

        Log.Info($"    Removing SPIs: {string.Join(", ", matches.Select(Bit.HexString))}");

        Send(to: sender, message: BuildResponse(ExchangeType.INFORMATIONAL, sendZeroHeader, _myCrypto,
            new PayloadDelete(deletePayload.ProtocolType, matches)));
    }

    private bool TryRemoveChild(byte[] deadSpi)
    {
        if (deadSpi.Length != 4) return false;

        var spi = Bit.BytesToUInt32(deadSpi);
        var removed = _thisSessionChildren.Remove(spi);

        if (removed) _sessionHost.RemoveChildSession(spi);
        else Log.Warn($"    Failed to remove session {Bit.HexString(deadSpi)}");

        return removed;
    }

    /// <summary>
    /// Send a final response to AUTH message, when we are responder.
    /// We are Established once that message is sent, and the
    /// remote gateway will consider the session established when
    /// it gets our reply.
    /// <p></p>
    /// This is related to <see cref="HandleAuthConfirm"/>
    /// </summary>
    private void HandleAuth(IkeMessage request, IPEndPoint sender, bool sendZeroHeader)
    {
        Log.Debug("        HandleAuth():: payloads incoming:", request.DescribeAllPayloads);

        var peerSkp = _peerCrypto?.SkP;
        if (peerSkp is null) throw new Exception("Peer SK-p not established before IKE_AUTH received");
        if (_peerNonce is null) throw new Exception("Peer N-once was not established before IKE_AUTH received");
        if (_previousRequestRawData is null) throw new Exception("Peer's previous raw request not stored during IKE_INIT_SA to use in IKE_AUTH");

        // read traffic selectors
        var tsi = request.GetPayload<PayloadTsi>() ?? throw new Exception("IKE_AUTH did not have an Traffic Select initiator payload");
        var tsr = request.GetPayload<PayloadTsr>() ?? throw new Exception("IKE_AUTH did not have an Traffic Select responder payload");

        var sa = request.GetPayload<PayloadSa>() ?? throw new Exception("IKE_AUTH did not have an SA payload");
        var idi = request.GetPayload<PayloadIDi>() ?? throw new Exception("IKE_AUTH did not have an IDi payload");
        var auth = request.GetPayload<PayloadAuth>();
        if (auth is null) throw new Exception("Peer requested EAP, which we don't support");

        var pskAuth = GeneratePskAuth(_previousRequestRawData, _localNonce, idi, peerSkp, _peerCrypto?.Prf);
        if (Bit.AreDifferent(pskAuth, auth.AuthData))
        {
            throw new Exception("PSK auth failed: initiator's hash did not match our expectations.\r\n\t" +
                                $"Expected {Bit.HexString(pskAuth)},\r\n\tbut got {Bit.HexString(auth.AuthData)}");
        }

        Log.Debug("    PSK auth agreed from this side");

        // pvpn/server.py:298
        var chosenChildProposal = sa.GetProposalFor(EncryptionTypeId.ENCR_AES_CBC);
        if (chosenChildProposal is null)
        {
            Log.Warn("    FATAL: could not find a compatible Child SA");
            // Try to reject by sending back an empty proposal. Not sure about this
            Send(to: sender, BuildResponse(ExchangeType.IKE_AUTH, sendZeroHeader, _myCrypto, new PayloadSa(new Proposal())));
            return;
        }

        var childKey = CreateChildKey(sender, chosenChildProposal, _peerNonce, _localNonce);
        Log.Debug($"    New ESP SPI = {childKey.SpiIn:x8}");
        chosenChildProposal.SpiData = Bit.UInt32ToBytes(childKey.SpiIn); // Used to refer to the child SA in ESP messages?
        chosenChildProposal.SpiSize = 4;

        if (_lastSentMessageBytes is null) throw new Exception("IKE_AUTH stage reached without recording a last sent message? Auth cannot proceed.");

        // pvpn/server.py:301
        var responsePayloadIdr = new PayloadIDr(IdType.ID_IPV4_ADDR, Settings.LocalIpAddress, 0, 0); // must be same as ipsec.conf, otherwise auth will fail
        var mySkp = _myCrypto?.SkP;
        if (mySkp is null) throw new Exception("Local SK-p not established before IKE_AUTH received");
        var authData = GeneratePskAuth(_lastSentMessageBytes, _peerNonce, responsePayloadIdr, mySkp, _peerCrypto?.Prf); // I think this is based on the last thing we sent
        Log.Debug($"    Auth data ({authData.Length} bytes) = {Bit.HexString(authData)}");

        Log.Debug($"    Chosen proposal: {Json.Freeze(chosenChildProposal)}");

        // pvpn/server.py:309
        // Send our IKE_AUTH message back
        var response = BuildResponse(ExchangeType.IKE_AUTH, sendZeroHeader, _myCrypto,
            new PayloadSa(chosenChildProposal),
            tsi, tsr, // just accept whatever traffic selectors. We're virtual.
            responsePayloadIdr,
            new PayloadAuth(AuthMethod.PSK, authData),
            new PayloadNotify(IkeProtocolType.NONE, NotifyId.REDIRECT_SUPPORTED, null, null)
        );

        var cpPayload = request.GetPayload<PayloadCp>();
        if (cpPayload is null) Log.Debug("    No Configuration (CP) payload");
        else Log.Debug("    Configuration (CP) payload present");

        // Send reply.
        Log.Info($"    Sending IKE_AUTH response to peer {sender.Address} : {sender.Port}");

        Send(to: sender, response);

        Log.Debug("    Setting state to established");
        State = SessionState.ESTABLISHED; // Should now have a full Child SA
        // Should now get INFORMATIONAL messages, possibly with some `IKE_DELETE` payloads to tell me about expired sessions.
    }
    
    /// <summary>
    /// Handle the reply to AUTH message, when we are the initiator.
    /// The remote gateway should already consider us as Established.
    /// <p></p>
    /// This is related to <see cref="HandleAuth"/>
    /// </summary>
    private void HandleAuthConfirm(IkeMessage request, IPEndPoint sender, bool sendZeroHeader)
    {
        Log.Debug("        HandleAuthConfirm():: payloads incoming:", request.DescribeAllPayloads);
        
        
        // The incoming message should have an Auth payload, which we use to confirm the PSK.
        // It should have TSi and TSr, which we would normally check to authorise, but we just accept as we're virtual.
        // It should have IDr for the peer gateway, which we would normally confirm, but we can ignore.
        // We should also get an SA payload with a SINGLE child session selected by the remote peer.
        // The SA will be used to confirm the ChildSA spi used for session keying.
        //
        // We MUST add a ChildSA session correctly if we exit without error.

        var peerSkp = _peerCrypto?.SkP;
        if (peerSkp is null) throw new Exception("Peer SK-p not established before IKE_AUTH received");
        if (_peerNonce is null) throw new Exception("Peer N-once was not established before IKE_AUTH received");
        if (_previousRequestRawData is null) throw new Exception("Peer's previous raw request not stored during IKE_INIT_SA to use in IKE_AUTH");

        var idr = request.GetPayload<PayloadIDr>() ?? throw new Exception("IKE_AUTH did not have an IDi payload");
        var auth = request.GetPayload<PayloadAuth>();
        if (auth is null) throw new Exception("Peer requested EAP, which we don't support");
        
        // Check for
        // Payload=Notification; ProtocolType=NONE; NotificationType=NO_PROPOSAL_CHOSEN; Spi=; InfoData=;
        var noPropMessage = request.GetPayload<PayloadNotify>(pl => pl.NotificationType == NotifyId.NO_PROPOSAL_CHOSEN);
        if (noPropMessage is not null)
        {
            Log.Critical("Peer did not accept any of the ChildSA proposals. Cannot continue.");
            return;
        }

        var pskAuth = GeneratePskAuth(_previousRequestRawData, _localNonce, idr, peerSkp, _peerCrypto?.Prf);
        if (Bit.AreDifferent(pskAuth, auth.AuthData))
        {
            throw new Exception("PSK auth failed: initiator's hash did not match our expectations.\r\n\t" +
                                $"Expected {Bit.HexString(pskAuth)},\r\n\tbut got {Bit.HexString(auth.AuthData)}");
        }

        Log.Debug("    PSK auth agreed from this side");

        var sa = request.GetPayload<PayloadSa>();
        var chosenChildProposal = sa?.GetProposalFor(EncryptionTypeId.ENCR_AES_CBC) ?? _lastSaProposal;
        if (chosenChildProposal is null)
        {
            Log.Warn("    FATAL: could not find a compatible Child SA");
            // Try to reject. Not sure about this
            ReplyNotAcceptable(sender, sendZeroHeader);
            return;
        }

        // IEB: Continue here. Need to check we generate the child SA with keys the right way around.
        var childKey = CreateChildKey(sender, chosenChildProposal, _peerNonce, _localNonce);
        Log.Debug($"    New ESP SPI = {childKey.SpiIn:x8}; spi_out={childKey.SpiOut:x8}");
        chosenChildProposal.SpiData = Bit.UInt32ToBytes(childKey.SpiIn); // Used to refer to the child SA in ESP messages?
        chosenChildProposal.SpiSize = 4;

        Log.Debug("    Setting state to established");
        State = SessionState.ESTABLISHED; // Should now have a full Child SA
        
        // Could now send INFORMATIONAL messages, possibly with some `IKE_DELETE` payloads to tell the peer about expired sessions.
    }

    // ReSharper disable CommentTypo
    /// <summary>
    /// PSK auth that matches what StrongSwan seems to do
    /// See src/libcharon/sa/ikev2/keymat_v2.c:659
    /// </summary>
    // ReSharper restore CommentTypo
    private byte[] GeneratePskAuth(byte[] messageData, byte[] nonce, PayloadIDx payload, byte[] skP, Prf? prf)
    {
        if (prf is null) throw new Exception("Tried to generate PSK auth before key exchange completed");

        Log.Debug("PSK message:", () => One(payload.Describe()));

        var prefix = new byte[] { (byte)payload.IdType, 0, 0, 0 };
        var peerId = payload.IdData;
        var idxTick = prefix.Concat(peerId).ToArray();
        var octetPad = prf.Hash(skP, idxTick);

        var bulk = messageData.Concat(nonce).Concat(octetPad).ToArray();

        Log.Crypto($"#### {Bit.Describe("IDx'", idxTick)}");
        Log.Crypto($"#### {Bit.Describe("SK_p", skP)}");
        Log.Crypto($"#### {Bit.Describe("prf(Sk_px, IDx')", octetPad)}");
        Log.Crypto($"#### {Bit.Describe("octets =  message + nonce + prf(Sk_px, IDx') ", messageData)}"); // expect ~ 1192 bytes

        var psk = Encoding.ASCII.GetBytes(Settings.PreSharedKeyString);
        var pad = Encoding.ASCII.GetBytes(Prf.IKEv2_KeyPad);
        var prfPskPad = prf.Hash(psk, pad);


        return prf.Hash(prfPskPad, bulk);
    }

    /// <summary>
    /// Converts a single item into an enumeration
    /// </summary>
    private static IEnumerable<T> One<T>(T thing) { yield return thing; }

    /// <summary>
    /// This sets up the crypto keys for a <see cref="ChildSa"/>,
    /// adds that child the the child list, and
    /// registers the child with the session host 
    /// </summary>
    private ChildSa CreateChildKey(IPEndPoint gateway, Proposal childProposal, byte[] peerNonce, byte[] localNonce)
    {
        // pvpn/server.py:237

        if (_skD is null) throw new Exception("SK-d was not initialised before trying to create a CHILD-SA. Key exchange failed?");
        if (_myCrypto?.Prf is null) throw new Exception("Crypto was not initialised before trying to create a CHILD SA.");

        // Gather up selected protocol, and check all results are valid
        var integId = childProposal.GetTransform(TransformType.INTEG)?.Id;
        if (integId is null) throw new Exception("Chosen proposal has no INTEG section");
        var cipherInfo = childProposal.GetTransform(TransformType.ENCR);
        if (cipherInfo is null) throw new Exception("Chosen proposal has no ENCR section");
        var keyLength = GetKeyLength(cipherInfo);
        if (keyLength is null) throw new Exception("Chosen proposal ENCR section has no KEY_LENGTH attribute");

        var seed = peerNonce.Concat(localNonce).ToArray();
        var cipher = new Cipher((EncryptionTypeId)cipherInfo.Id, keyLength.Value);
        var check = new Integrity((IntegId)integId);

        var totalSize = 2 * check.KeySize + 2 * cipher.KeySize;
        var keySource = _myCrypto.Prf.PrfPlus(_skD, seed, totalSize);

        var idx = 0;
        var skEi = Bit.Subset(cipher.KeySize, keySource, ref idx);
        var skAi = Bit.Subset(check.KeySize, keySource, ref idx);
        var skEr = Bit.Subset(cipher.KeySize, keySource, ref idx);
        var skAr = Bit.Subset(check.KeySize, keySource, ref idx);

        var cryptoIn = new IkeCrypto(cipher, check, null, skEi, skAi, null, null);
        var cryptoOut = new IkeCrypto(cipher, check, null, skEr, skAr, null, null);


        var randomSpi = new byte[4];
        RandomNumberGenerator.Fill(randomSpi);

        var spiOut = Bit.BytesToUInt32(randomSpi);
        var childSa = new ChildSa(IpV4Address.FromEndpoint(gateway), randomSpi, childProposal.SpiData, cryptoIn, cryptoOut, _server, this);

        // '_thisSessionChildren' using spiOut, '_sessionHost' using spiIn.
        // Note: we may need to fiddle these around (or use both) if sessions don't look like they're working
        _sessionHost.AddChildSession(childSa); // this gets us the 32-bit SA used for ESA, not the 64-bit used for key exchange
        _thisSessionChildren.Add(spiOut, childSa);

        return childSa;
    }

    /// <summary>
    /// Not yet implemented. Call out to an external server, try to start an IKE/SA session
    /// </summary>
    public void RequestNewSession(IPEndPoint target)
    {
        // Set up a proposal for crypto settings
        // Normally, a VPN system would send a complete set of what they support,
        // but here we are just sending over a minimal set we expect the other
        // side to accept.
        var defaultProposal = new Proposal
        {
            Number = 1, // must start at 1, not 0
            Protocol = IkeProtocolType.IKE,
        };

        // We only support one type of encryption, so supply that
        defaultProposal.Transforms.Add(new Transform
        {
            Type = TransformType.ENCR,
            Id = (uint)EncryptionTypeId.ENCR_AES_CBC,
            Attributes = { new TransformAttribute(TransformAttr.KEY_LENGTH, 256) }
        });

        // Supply the key exchange we know M-Pesa want
        defaultProposal.Transforms.Add(new Transform
        {
            Type = TransformType.DH,
            Id = (uint)DhId.DH_14
        });

        // Supply a hash function for checksums
        defaultProposal.Transforms.Add(new Transform
        {
            Type = TransformType.INTEG,
            Id = (uint)IntegId.AUTH_HMAC_SHA2_256_128
        });

        // Supply a hash function for random number generation
        defaultProposal.Transforms.Add(new Transform
        {
            Type = TransformType.PRF,
            Id = (uint)PrfId.PRF_HMAC_SHA2_256
        });

        _keyExchange ??= BCDiffieHellman.CreateForGroup(DhId.DH_14) ?? throw new Exception("Failed to generate key exchange when generating new session");
        _keyExchange.get_our_public_key(out var newPublicKey);

        _initMessage = BuildSerialMessage(ExchangeType.IKE_SA_INIT, MessageFlag.Initiator, false, false, null, _localSpi, 0, 0,
            new PayloadSa(defaultProposal),
            new PayloadNonce(_localNonce),
            new PayloadKeyExchange(DhId.DH_14, newPublicKey), // Pre-start our preferred exchange
            new PayloadNotify(IkeProtocolType.NONE, NotifyId.NAT_DETECTION_DESTINATION_IP, Array.Empty<byte>(), Bit.RandomBytes(20)),
            new PayloadNotify(IkeProtocolType.NONE, NotifyId.NAT_DETECTION_SOURCE_IP, Array.Empty<byte>(), Bit.RandomBytes(20))
        );

        State = SessionState.IKE_INIT_SENT;
        Send(to: target, _initMessage);
    }

    /// <summary>
    /// We are the initiator, and we got an IKE_SA_INIT message.
    /// We should now check the message is acceptable; and if so, send the first IKE_AUTH message
    /// <p></p>
    /// This is closely related to <see cref="HandleSaInit"/>
    /// </summary>
    private void HandleSaConfirm(IkeMessage request, IPEndPoint sender, bool sendZeroHeader) // ike/protocol.py:91
    {
        Log.Debug("        Session: IKE_SA_INIT received (as initiator)");
        Log.Debug("        HandleSaInit():: payloads:", request.DescribeAllPayloads);
        
        _peerNonce ??= request.GetPayload<PayloadNonce>()?.Data;
        
        // Check to see if exactly one SA was chosen
        var saPayload = request.GetPayload<PayloadSa>();

        if (saPayload is null || saPayload.Proposals.Count != 1)
        {
            Log.Warn($"        Session: Peer did not agree with our proposition. Sending rejection to {sender.Address}:{sender.Port}");
            Send(to: sender, message: BuildResponse(ExchangeType.IKE_SA_INIT, sendZeroHeader, null,
                new PayloadNotify(IkeProtocolType.IKE, NotifyId.INVALID_KE_PAYLOAD, null, null)
            ));
            return;
        }
        
        // Check to see it's the one we offered (would need to implement negotiation if not)
        var chosenProposal = saPayload.GetProposalFor(EncryptionTypeId.ENCR_AES_CBC); // we only support AES CBC mode at the moment, and M-Pesa only does DH-14
        var preferredDiffieHellman = chosenProposal?.GetTransform(TransformType.DH)?.Id;
        var payloadKe = request.GetPayload<PayloadKeyExchange>();

        if (chosenProposal is null || preferredDiffieHellman != (uint)DhId.DH_14 || payloadKe is null)
        {
            Log.Warn($"        Session: Peer is trying to negotiate a different crypto setting. This is not currently supported. Sending rejection to {sender.Address}:{sender.Port}");
            Send(to: sender, message: BuildResponse(ExchangeType.IKE_SA_INIT, sendZeroHeader, null,
                new PayloadNotify(IkeProtocolType.IKE, NotifyId.INVALID_KE_PAYLOAD, null, null)
            ));
            return;
        }
        
        // Should be able to finish key exchange now.
        if (_keyExchange is null) throw new Exception($"Key exchange object was null in {nameof(HandleSaConfirm)}. This should have been setup in {nameof(RequestNewSession)}");
        _keyExchange.set_their_public_key(payloadKe.KeyData);
        _keyExchange.get_shared_secret(out var secret);
        
        // create keys from exchange result. If something went wrong, we will end up with a checksum failure
        CreateKeyAndCrypto(chosenProposal, secret, null);
        
        var mainIDi = new PayloadIDi(IdType.ID_IPV4_ADDR, Settings.LocalIpAddress, 0, IpProtocol.ANY);
        mainIDi.ToBytes();// just to trigger the serialisation
        
        var peerIDr = new PayloadIDr(IdType.ID_IPV4_ADDR, Gateway.Value, 0, IpProtocol.ANY);
        var mySkP = _myCrypto?.SkP;
        var peerSkp = _peerCrypto?.SkP;
        if (_peerNonce is null) throw new Exception("Peer n-Once not established before IKE_AUTH construction");
        if (mySkP is null) throw new Exception("SK-p not established before IKE_AUTH construction");
        if (peerSkp is null) throw new Exception("Peer SK-p not established before IKE_AUTH construction");
        if (_initMessage is null) throw new Exception("No init message recorded before IKE_AUTH construction, auth cannot continue.");
        
        var pskAuth = GeneratePskAuth(_initMessage, _peerNonce, mainIDi, mySkP, _myCrypto?.Prf);
        Log.Debug($"Sending PSK auth:\r\n{Bit.HexString(pskAuth)}");
        
        var spiOut = new byte[4];
        RandomNumberGenerator.Fill(spiOut);
        // 2022-09-01T14:41 (utc)     Chosen proposal: {"Number":1,"Protocol":"ESP","SpiSize":4,"SpiData":"E05erw==",
        // "TransformCount":3,"Transforms":[
        // {"Length":12,"Type":"ENCR","Id":12,"Attributes":[{"Size":4,"ValueBytes":"","Value":128,"Type":"KEY_LENGTH"}],"Size":4,"Description":"ENCR id=EncryptionTypeId.ENCR_AES_CBC attr=[KEY_LENGTH: 128]"},
        // {"Length":8,"Type":"INTEG","Id":12,"Attributes":[],"Size":0,"Description":"INTEG id=IntegId.AUTH_HMAC_SHA2_256_128 attr=[]"},
        // {"Length":8,"Type":"ESN","Id":0,"Attributes":[],"Size":0,"Description":"ESN id=EsnId.NO_ESN attr=[]"}],
        // "Size":36}

        var espProposal = new Proposal
        {
            Number = 1,
            Protocol = IkeProtocolType.ESP,
            SpiData = spiOut,
            Transforms = {
                new Transform
                {
                    Type = TransformType.ENCR,
                    Id = (uint)EncryptionTypeId.ENCR_AES_CBC,
                    Attributes = { new TransformAttribute(TransformAttr.KEY_LENGTH, 128) }
                },
                new Transform
                {
                    Type = TransformType.INTEG,
                    Id = (uint)IntegId.AUTH_HMAC_SHA2_256_128
                },
                new Transform
                {
                    Type = TransformType.ESN,
                    Id = (uint)EsnId.NO_ESN
                }
            }
        };
        
        _lastSaProposal = espProposal;
        
        // IKE flags Initiator, message id=1, first payload=SK
        Log.Trace("Building AUTH/SA confirmation message, switching to port 4500");
        var msgBytes = BuildSerialMessage(ExchangeType.IKE_AUTH, MessageFlag.Initiator, useAlternateChecksum: false,
            sendZeroHeader:true, // because we are switching to 4500
            _myCrypto, _localSpi, _peerSpi, msgId: 1,
            
            mainIDi,
            new PayloadNotify(IkeProtocolType.NONE, NotifyId.INITIAL_CONTACT, null, null),
            peerIDr,
            new PayloadAuth(AuthMethod.PSK, pskAuth),
            new PayloadSa(espProposal),
            new PayloadTsi(Settings.LocalTrafficSelector), // our address ranges,
            new PayloadTsr(Settings.RemoteTrafficSelector), // expected ranges on their side
            
            new PayloadNotify(IkeProtocolType.NONE, NotifyId.ADDITIONAL_IP4_ADDRESS, null, Settings.LocalTrafficSelector.StartAddress), // ??? test
            
            new PayloadNotify(IkeProtocolType.NONE, NotifyId.MOBIKE_SUPPORTED, null, null) // Enable mobility extensions
            // Notifications for extra IP addresses could go here, but we don't support them yet.
        );
        
        // The message should be something that VirtualVpn.Crypto.IkeCrypto.VerifyChecksumInternal would give the OK to
        var ok = _myCrypto!.VerifyChecksum(msgBytes.Skip(4).ToArray());
        if (!ok) Log.Warn("Message did not pass our own checksum. Likely to be rejected by peer.");
        
        // Switch to 4500 port now. The protocol works without it, but VirtualVPN assumes the switch will happen.
        // See https://docs.strongswan.org/docs/5.9/features/mobike.html
        Send(to: new IPEndPoint(sender.Address, port:4500), message: msgBytes);
        //Send(to: sender, message: msgBytes); // this would stay on 500, which I think is allowed. But it's not normal
        State = SessionState.AUTH_SENT;
    }
    
    /// <summary>
    /// We are the responder, and we got an IKE_SA_INIT message.
    /// We should try to find an acceptable set of crypto proposals;
    /// and if so, send another IKE_SA_INIT message in reply.
    /// <p></p>
    /// This is closely related to <see cref="HandleSaConfirm"/>
    /// </summary>
    private void HandleSaInit(IkeMessage request, IPEndPoint sender, bool sendZeroHeader)
    {
        Log.Debug("        Session: IKE_SA_INIT received (as responder)");
        Log.Debug("        HandleSaInit():: payloads:", request.DescribeAllPayloads);

        _peerNonce = request.GetPayload<PayloadNonce>()?.Data;

        // pick a proposal we can work with, if any
        var saPayload = request.GetPayload<PayloadSa>();
        if (saPayload is null) throw new Exception("IKE_SA_INIT did not contain any SA proposals");

        var chosenProposal = saPayload.GetProposalFor(EncryptionTypeId.ENCR_AES_CBC); // we only support AES CBC mode at the moment, and M-Pesa only does DH-14
        var payloadKe = request.GetPayload<PayloadKeyExchange>();

        var preferredDiffieHellman = chosenProposal?.GetTransform(TransformType.DH)?.Id;

        // If there is nothing we can agree on, this session is dead. Send an error message
        if (chosenProposal is null || payloadKe is null || preferredDiffieHellman is null || payloadKe.KeyData.Length < 1)
        {
            // pvpn/server.py:274
            Log.Warn($"        Session: Could not find an agreeable proposition. Sending rejection to {sender.Address}:{sender.Port}");
            Send(to: sender, message: BuildResponse(ExchangeType.IKE_SA_INIT, sendZeroHeader, null,
                new PayloadNotify(IkeProtocolType.IKE, NotifyId.INVALID_KE_PAYLOAD, null, null)
            ));
            return;
        }

        // If we can agree on a proposition, but the initiator's default is not acceptable,
        // then we will make a new proposal with a new key exchange.
        if ((uint)payloadKe.DiffieHellmanGroup != preferredDiffieHellman.Value)
        {
            Log.Info("        Session: We agree on a viable proposition, but it was not the default. Requesting switch.");

            var reKeyMessage = BuildResponse(ExchangeType.IKE_SA_INIT, sendZeroHeader, null,
                new PayloadSa(chosenProposal),
                new PayloadNotify(IkeProtocolType.IKE, NotifyId.INVALID_KE_PAYLOAD, Bit.UInt64ToBytes(request.SpiI), Bit.UInt16ToBytes((ushort)DhId.DH_14))
            );

            Send(to: sender, message: reKeyMessage);
            _peerMsgId--; // this is not going to count as a sequenced message
            return;
        }

        // build key
        Log.Debug($"        Session: We agree on a viable proposition, and it is the default. Continue with key share for {payloadKe.DiffieHellmanGroup.ToString()}" +
                  $" Supplied length is {payloadKe.KeyData.Length} bytes");

        _keyExchange ??= BCDiffieHellman.CreateForGroup(DhId.DH_14) ?? throw new Exception($"Failed to create key exchange for group {payloadKe.DiffieHellmanGroup.ToString()}");
        _keyExchange.set_their_public_key(payloadKe.KeyData);
        _keyExchange.get_our_public_key(out var publicKey);
        _keyExchange.get_shared_secret(out var secret);

        // create keys from exchange result. If something went wrong, we will end up with a checksum failure
        CreateKeyAndCrypto(chosenProposal, secret, null);

        var saMessage = BuildResponse(ExchangeType.IKE_SA_INIT, sendZeroHeader, null,
            new PayloadSa(chosenProposal),
            new PayloadNonce(_localNonce),
            new PayloadKeyExchange(payloadKe.DiffieHellmanGroup, publicKey),
            new PayloadNotify(IkeProtocolType.NONE, NotifyId.NAT_DETECTION_DESTINATION_IP, Array.Empty<byte>(), Bit.RandomBytes(20)),
            new PayloadNotify(IkeProtocolType.NONE, NotifyId.NAT_DETECTION_SOURCE_IP, Array.Empty<byte>(), Bit.RandomBytes(20))
        );

        Log.Debug($"        Session: Sending IKE_SA_INIT reply to {sender.Address}:{sender.Port}");
        Send(to: sender, message: saMessage);
        State = SessionState.SA_SENT;

        Log.Debug("        Session: Completed IKE_SA_INIT, transition to state=SA_SENT");
    }

    /// <summary>
    /// Generate key from DH exchange, build crypto protocols.
    /// </summary>
    private void CreateKeyAndCrypto(Proposal proposal, byte[] sharedSecret, byte[]? oldSkD)
    {
        // Check the state is ok
        if (_peerNonce is null) throw new Exception("Did not receive N-once from peer");

        // Gather up selected protocol, and check all results are valid
        var prfId = proposal.GetTransform(TransformType.PRF)?.Id;
        if (prfId is null) throw new Exception("Chosen proposal has no PRF section");
        var integId = proposal.GetTransform(TransformType.INTEG)?.Id;
        if (integId is null) throw new Exception("Chosen proposal has no INTEG section");
        var cipherInfo = proposal.GetTransform(TransformType.ENCR);
        if (cipherInfo is null) throw new Exception("Chosen proposal has no ENCR section");
        var keyLength = GetKeyLength(cipherInfo);
        if (keyLength is null) throw new Exception("Chosen proposal ENCR section has no KEY_LENGTH attribute");
        
        IkeCrypto.CreateKeysAndCryptoInstances(
            _weAreInitiator,
            _peerNonce, _localNonce, sharedSecret,
            Bit.UInt64ToBytes(_peerSpi), Bit.UInt64ToBytes(_localSpi),
            (PrfId)prfId, (IntegId)integId, (EncryptionTypeId)cipherInfo.Id, keyLength.Value, oldSkD,
            out _skD, out _myCrypto, out _peerCrypto
        );
    }


    /// <summary>
    /// Find a transform attribute with type of key-length,
    /// and return the value
    /// </summary>
    private int? GetKeyLength(Transform info)
    {
        return info.Attributes.FirstOrDefault(a => a.Type == TransformAttr.KEY_LENGTH)?.Value;
    }

    private void Send(IPEndPoint to, byte[] message)
    {
        _lastContact = to;
        _lastSentMessageBytes = message;
        _server.SendRaw(message, to);

        if (Settings.CaptureTraffic)
        {
            var name = Settings.FileBase + $"IKEv2-Reply_{_peerMsgId}_Port-{to.Port}_IKE.bin";
            File.WriteAllBytes(name, message);
        }
    }

    /// <summary>
    /// Throw an exception if we're not in the expected state.
    /// Otherwise do nothing
    /// </summary>
    private void AssertState(SessionState expected, IkeMessage ikeMessage)
    {
        if (State != expected)
        {
            Log.Debug(Json.Freeze(ikeMessage));
            throw new Exception($"Expected to be in state {expected.ToString()}, but was in {State.ToString()}");
        }

        Log.Debug($"        Session: State correct: {State.ToString()} = {expected.ToString()}");
    }

    public void NotifyIpAddresses(IpV4Address address)
    {
        // HACK - just send a notify with a fixed IP address
        if (_lastContact is null)
        {
            Log.Error("Can't send IP addresses -- I don't have a last contact address");
            return;
        }

        // This currently kills the session? Maybe if we've got more than one?

        var response = BuildResponse(ExchangeType.INFORMATIONAL, true, _myCrypto,
            new PayloadNotify(IkeProtocolType.NONE, NotifyId.ADDITIONAL_IP4_ADDRESS, null, address.Value)
        );

        Send(to: _lastContact, response);
    }

    public void UpdateTrafficTimeout()
    {
        LastTouchTimer.Restart();
    }
}
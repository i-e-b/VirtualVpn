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
using VirtualVpn.Logging;

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

    private byte[]? _initMessage;
    private byte[]? _lastSentMessageBytes;
    private byte[]? _previousRequestRawData;
    
    private byte[]? _peerNonce;
    private byte[]? _skD;

    private readonly Dictionary<uint, ChildSa> _thisSessionChildren = new();
    private SessionState _state;
    private IPEndPoint? _lastContact;
    
    private bool _haveSentMobIkeAddresses; // Have we responded with network addresses?
    private byte[]? _localSpiOut; // for spawned child SA
    private readonly byte[] _localNonce;
    private int _peerMsgId;
    private int _myMsgId;
    private int _mobIkeMsgId;

    private ulong _peerSpi;
    private readonly ulong _localSpi;
    private ulong _incomingMessageCount, _outgoingMessageCount;
    private readonly DateTime _startDateTime;

    //## Algorithmic selections (negotiated with peer) ##//

    private IkeCrypto? _myCrypto;
    private IkeCrypto? _peerCrypto;
    private BCDiffieHellman? _keyExchange;
    private Proposal? _lastSaProposal;

    //## Locked for session ##//
    
    private readonly IUdpServer _server; // note: should increment _seqOut when sending
    private readonly ISessionHost _sessionHost;
    private readonly bool _weAreInitiator;

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
        _myMsgId = 0;
        _mobIkeMsgId = 0;
        
        _startDateTime = DateTime.UtcNow;
        _incomingMessageCount = 0;
        _outgoingMessageCount = 0;
        
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

        switch (State)
        {
            case SessionState.ESTABLISHED:
            {
                if (LastTouchTimer.Elapsed < Settings.EspTimeout) return;
                
                EndConnectionWithPeer(); // fire a DELETE message, but don't wait for reply
            
                Log.Critical($"Session {_localSpi:x} timed-out after establishment. Are keep-alive messages not arriving?");
                foreach (var child in _thisSessionChildren)
                {
                    Log.Trace($"Removing child SA {child.Key:x}; spi-in={child.Value.SpiIn:x}, spi-out={child.Value.SpiOut:x}");
                    _sessionHost.RemoveChildSession(child.Value.SpiIn, child.Value.SpiOut);
                }

                _sessionHost.RemoveSession(wasRemoteRequest: false, _localSpi, _peerSpi);
                
                State = SessionState.DELETED;
                break;
            }
            case SessionState.DELETED:
            {
                Log.Info($"Removing deleted session {_localSpi:x}");
                _sessionHost.RemoveSession(wasRemoteRequest: false, _localSpi, _peerSpi);

                foreach (var child in _thisSessionChildren)
                {
                    Log.Trace($"Removing child SA {child.Key:x}; spi-in={child.Value.SpiIn:x}, spi-out={child.Value.SpiOut:x}");
                    _sessionHost.RemoveChildSession(child.Value.SpiIn, child.Value.SpiOut);
                }

                break;
            }
            default:
            {
                if (LastTouchTimer.Elapsed < Settings.IkeTimeout) return;
                
                EndConnectionWithPeer(); // fire a DELETE message, but don't wait for reply
            
                Log.Critical($"Session {_localSpi:x} timed-out during negotiation (state={State.ToString()}). The session will be abandoned.");
                _sessionHost.RemoveSession(wasRemoteRequest: false, _localSpi, _peerSpi);
                
                State = SessionState.DELETED;
                break;
            }
        }
    }

    public bool EndConnectionWithPeer()
    {
        Log.Info("Ending session by local request");
        // Check we're in a fit state
        if (_lastContact is null)
        {
            Log.Warn($"EndConnectionWithPeer: I don't have a last contact address, will assume gateway at {Gateway.AsString}:4500");
            _lastContact = Gateway.MakeEndpoint(4500);
        }

        // List SPIs for this session
        var spiList = new List<byte[]>{
            Bit.UInt64ToBytes(_localSpi),
            Bit.UInt64ToBytes(_peerSpi)
        };

        // Send the delete
        var response = BuildResponse(ExchangeType.INFORMATIONAL, _myMsgId++, sendZeroHeader: true, _myCrypto,
            new PayloadDelete(IkeProtocolType.IKE, spiList)
        );

        Log.Warn($"Sending DELETE message to gateway {_lastContact.ToString()}. MsgId={_myMsgId}, localSpi={_localSpi:x16}, peerSpi={_peerSpi:x16}");
        Send(to: _lastContact, response);
        
        // Switch our mode
        State = SessionState.DELETED; // event pump should unbind the session and it's child soon.
        _sessionHost.RemoveSession(false, _localSpi, _peerSpi);
        return true;
    }
    
    public bool EndChildSaWithPeer(ChildSa child)
    {
        // Check we're in a fit state
        if (_lastContact is null)
        {
            Log.Error("Tried to cleanly end session, but can't send message -- I don't have a last contact address");
            return false;
        }

        // List SPIs for this session
        var spiList = new List<byte[]>{
            Bit.UInt32ToBytes(child.SpiIn),
            Bit.UInt32ToBytes(child.SpiOut)
        };

        // Send the delete
        var response = BuildResponse(ExchangeType.INFORMATIONAL, _myMsgId++, sendZeroHeader: true, _myCrypto,
            new PayloadDelete(IkeProtocolType.IKE, spiList)
        );

        Log.Warn($"Sending DELETE message to gateway {_lastContact.ToString()}. MsgId={_myMsgId}, localSpi={_localSpi:x16}, peerSpi={_peerSpi:x16}");
        Send(to: _lastContact, response);
        
        // Switch our mode
        State = SessionState.DELETED; // event pump should unbind the session and it's child soon.
        return true;
    }

    // pvpn/server.py:253
    private byte[] BuildResponse(ExchangeType exchange, int msgId, bool sendZeroHeader, IkeCrypto? crypto, params MessagePayload[] payloads)
    {
        return _weAreInitiator
            ? BuildSerialMessage(exchange, MessageFlag.Initiator | MessageFlag.Response, sendZeroHeader, crypto, _localSpi, _peerSpi, msgId, payloads)
            : BuildSerialMessage(exchange, MessageFlag.Response, sendZeroHeader, crypto, _peerSpi, _localSpi, msgId, payloads);
    }

    public static byte[] BuildSerialMessage(ExchangeType exchange, MessageFlag flags, bool sendZeroHeader, IkeCrypto? crypto,
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

        return resp.ToBytes(sendZeroHeader, crypto); // will wrap payloads in PayloadSK if we have crypto
    }

    /// <summary>
    /// Handle an incoming key exchange message
    /// </summary>
    public void HandleIke(IkeMessage request, IPEndPoint sender, bool sendZeroHeader)
    {
        try
        {
            _incomingMessageCount++;
            Log.Debug($"    Incoming IKE message {request.Exchange.ToString()} {request.MessageId}");
            HandleIkeInternal(request, sender, sendZeroHeader);

            _previousRequestRawData = request.RawData; // needed to do PSK auth
        }
        catch (Exception ex)
        {
            Log.Error("Failed to handle IKE message", ex);
        }
    }

    /// <summary>
    /// THIS IS THE CORE OF MESSAGE ROUTING
    /// </summary>
    private void HandleIkeInternal(IkeMessage request, IPEndPoint sender, bool sendZeroHeader)
    {
        // pvpn/server.py:260
        LastTouchTimer.Restart();

        // Update our records if the remote has provided an SPI
        if (_weAreInitiator && _peerSpi == 0 && request.SpiR != 0) { _peerSpi = request.SpiR; }

        // Check for peer requesting a repeat of last message
        if (request.MessageId == _peerMsgId - 1)
        {
            // Might be restart ID of next exchange type?
            if (request.MessageId == 0 && request.Exchange == ExchangeType.INFORMATIONAL)
            {
                Log.Debug("Got message ID=0 and information exchange. This should be some kind of keep alive? Sending reply back.");
                _peerMsgId = 0;
            }
            else
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
        }
        
        // We should have crypto now, as long as we're out of IKE_SA_INIT phase
        try
        {
            request.ReadPayloadChain(_peerCrypto); // pvpn/server.py:266
        }
        catch (BadSessionException ex)
        {
            Log.Error("Error indicates session is bad. Sending DELETE", ex);
            EndConnectionWithPeer();
            return;
        }

        // make sure we're in sequence
        if (request.MessageId != _peerMsgId)
        {
            if (request.MessageId > _peerMsgId)
            {
                Log.Trace($"Advancing peer message ID from {_peerMsgId} to {request.MessageId}");
                _peerMsgId = (int)request.MessageId;
            }
            else
            {
                Log.Warn($"Request is out of sequence. Expected {_peerMsgId}, but got {request.MessageId}. Will reset");
                Log.Debug($"Out of sequence request: exchange type={request.Exchange.ToString()}, flags={request.MessageFlag.ToString()}, payloads:", request.DescribeAllPayloads);
                
                _peerMsgId = (int)request.MessageId;
            }
        }

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
                        throw new Exception($"Received {nameof(ExchangeType.IKE_SA_INIT)}," +
                                            $" so expected to be in state {nameof(SessionState.INITIAL)} or {nameof(SessionState.IKE_INIT_SENT)}," +
                                            $" but was in {State.ToString()}");
                }

                break;

            case ExchangeType.IKE_AUTH: // pvpn/server.py:287
                switch (State)
                {
                    case SessionState.SA_SENT:
                    {
                        Log.Info("IKE_AUTH received, we are responder");
                        HandleAuth(request, sender, sendZeroHeader);
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
                        Log.Info("Taking down this connection. If 'always' is set, a new session should be started.");
                        EndConnectionWithPeer();
                        break;
                    }
                    default:
                        throw new Exception($"Received {nameof(ExchangeType.IKE_AUTH)}," +
                                            $" so expected to be in state {nameof(SessionState.SA_SENT)} or {nameof(SessionState.AUTH_SENT)}," +
                                            $" but was in {State.ToString()}");
                }

                break;

            case ExchangeType.INFORMATIONAL: // pvpn/server.py:315
                AssertState(SessionState.ESTABLISHED, request);
                Log.Debug("INFORMATIONAL received");
                HandleInformational(request, sender, sendZeroHeader);
                break;

            case ExchangeType.CREATE_CHILD_SA: // pvpn/server.py:340
                AssertState(SessionState.ESTABLISHED, request);
                HandleSessionReKey(request, sender, sendZeroHeader);
                break;


            default:
                throw new Exception($"Unexpected request: {request.Exchange.ToString()}");
        }
    }

    /// <summary>
    /// Handle CREATE_CHILD_SA for an established session.
    /// This is very similar to <see cref="HandleAuth"/> and <see cref="HandleAuthConfirm"/>
    /// </summary>
    private void HandleSessionReKey(IkeMessage request, IPEndPoint sender, bool sendZeroHeader)
    { // pvpn/server.py:340
        
        Log.Info($"Re-key requested for session {_localSpi:x} / {_peerSpi:x}");
        
        var sa = request.GetPayload<PayloadSa>() ?? throw new Exception("CREATE_CHILD_SA did not have an SA payload");
        var chosenChildProposal = sa.GetProposalFor(EncryptionTypeId.ENCR_AES_CBC);
        if (chosenChildProposal is null)
        {
            Log.Warn("    FATAL: could not find a compatible Child SA during re-key");
            // Try to reject by sending back an empty proposal. Not sure about this
            Send(to: sender, BuildResponse(ExchangeType.CREATE_CHILD_SA, _peerMsgId, sendZeroHeader, _myCrypto, new PayloadSa(new Proposal())));
            return;
        }

        if (chosenChildProposal.Protocol != IkeProtocolType.IKE) // pvpn/server.py:343
        {
            var tsi = request.GetPayload<PayloadTsi>() ?? throw new Exception(@"Protocol error: Non-IKE CREATE_CHILD_SA without a TSi.");
            var tsr = request.GetPayload<PayloadTsr>() ?? throw new Exception(@"Protocol error: Non-IKE CREATE_CHILD_SA without a TSr.");
            var notify = request.GetPayload<PayloadNotify>(p => p.NotificationType == NotifyId.REKEY_SA) ?? throw new Exception(@"Protocol error: Non-IKE CREATE_CHILD_SA without a REKEY_SA.");
            var matchingChild = TryGetMatchingChildSession(notify.SpiData);
            if (matchingChild is null) throw new Exception(@"Protocol error: Non-IKE CREATE_CHILD_SA tried to re-key a session we don't know");
            
            var peerNonce = request.GetPayload<PayloadNonce>()?.Data ?? throw new Exception(@"Protocol error: Non-IKE CREATE_CHILD_SA did not have a valid peer n-once");
            var localNonce = Bit.RandomNonce();
            
            var newChild = CreateChildKey(Gateway, chosenChildProposal, peerNonce, localNonce, tsi);
            chosenChildProposal.SpiData = Bit.UInt32ToBytes(newChild.SpiIn);
            
            Log.Info("Re-key session. Created new ChildSA, sending confirmation message");
            
            // pvpn/server.py:358 & pvpn/server.py:371
            // Send our message back
            var response = BuildResponse(ExchangeType.CREATE_CHILD_SA, _peerMsgId, sendZeroHeader, _myCrypto,
                new PayloadNotify(chosenChildProposal.Protocol, NotifyId.REKEY_SA, Bit.UInt32ToBytes(matchingChild.SpiIn), null),
                new PayloadNonce(localNonce),
                new PayloadSa(chosenChildProposal),
                tsi, tsr // just accept whatever traffic selectors. We're virtual.
            );
            Send(to: sender, message: response);
            return;
        }

        Log.Critical("Remote peer tried to re-negotiate the whole session. Will end this one and wait for a new session.");
        EndConnectionWithPeer();
    }

    private ChildSa? TryGetMatchingChildSession(byte[] notifySpiData)
    {
        var spi = Bit.BytesToUInt32(notifySpiData);
        return _thisSessionChildren.Values.FirstOrDefault(c=>c.SpiIn == spi || c.SpiOut == spi);
    }

    /// <summary>
    /// Handle a new IKE_AUTH during established state.
    /// <p></p>
    /// This is for signalling changes 
    /// https://datatracker.ietf.org/doc/html/rfc4555
    /// </summary>
    private void HandleMobIke(IkeMessage request, IPEndPoint sender, bool sendZeroHeader)
    {
        // TODO: implement this. Probably need to send a correctly formed reply
        Log.Debug("        HandleMobIke():: payloads incoming:", request.DescribeAllPayloads);
        Log.Debug($"        sender={sender.Address}:{sender.Port}, zero pad={sendZeroHeader}");
        
        Log.Warn("Received MobIKE, but ignoring it.");
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
        var message = BuildSerialMessage(ExchangeType.IKE_SA_INIT, MessageFlag.Initiator | MessageFlag.Response, sendZeroHeader, null, _localSpi, _peerSpi, _peerMsgId,
            new PayloadDelete(IkeProtocolType.IKE, Array.Empty<byte[]>())
        );

        State = SessionState.DELETED;
        Log.Trace($"Sending 'not acceptable' message. Message ID={_peerMsgId}");
        Send(to: sender, message);
    }

    private void HandleInformational(IkeMessage request, IPEndPoint sender, bool sendZeroHeader)
    {
        // pvpn/server.py:315
        Log.Debug("        HandleInformational():: payloads incoming:", request.DescribeAllPayloads);

        // Check for any sessions the other side wants to remove
        var deletePayload = request.GetPayload<PayloadDelete>();

        if (deletePayload is null)
        {
            Log.Debug("No delete payloads found in Informational packet. Might reply, but nothing else");
            Log.Trace($"Found payloads: {string.Join(", ", request.Payloads.Select(p => p.Type.ToString()))};");
            
            var mobIkeFlag = request.GetPayload<PayloadNotify>(pl => pl.NotificationType == NotifyId.UPDATE_SA_ADDRESSES);
            if (mobIkeFlag is not null)
            {
                Log.Info("Received MOB-IKE update.");
                HandleMobIke(request, sender, sendZeroHeader);
                return;
            }

            // Nothing to do, but we must reply
            if (_weAreInitiator)
            {
                HandleMobIkeHandshake(request, sender, sendZeroHeader);
                return;
            }
            
            // Ping an empty message back
            Send(to: sender, message: BuildResponse(ExchangeType.INFORMATIONAL, _peerMsgId, sendZeroHeader, _myCrypto));
            return;
        }

        if (deletePayload.ProtocolType == IkeProtocolType.IKE) // pvpn/server.py:321
        {
            // This session should be removed?
            Log.Info($"    Removing entire session {_localSpi:x16}");
            foreach (var childSa in _thisSessionChildren)
            {
                _sessionHost.RemoveChildSession(childSa.Value.SpiIn, childSa.Value.SpiOut);
            }
            
            _sessionHost.RemoveSession(wasRemoteRequest: true, _localSpi, _peerSpi);

            State = SessionState.DELETED;
            _thisSessionChildren.Clear();
            Send(to: sender, message: BuildResponse(ExchangeType.INFORMATIONAL, _peerMsgId, sendZeroHeader, _myCrypto, deletePayload));
            return;
        }

        if (deletePayload.SpiList.Count < 1)
        {
            Log.Warn("    Received an empty delete list");
            Send(to: sender, message: BuildResponse(ExchangeType.INFORMATIONAL, _peerMsgId, sendZeroHeader, _myCrypto, deletePayload));
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

        Send(to: sender, message: BuildResponse(ExchangeType.INFORMATIONAL, _peerMsgId, sendZeroHeader, _myCrypto,
            new PayloadDelete(deletePayload.ProtocolType, matches)));
    }

    private void HandleMobIkeHandshake(IkeMessage request, IPEndPoint sender, bool sendZeroHeader)
    {
        if (request.MessageId != _mobIkeMsgId) Log.Warn($"Treating message as MobIke handshake, but it was out of sequence- expected {_mobIkeMsgId}, got {request.MessageId}. Will reset");
        _mobIkeMsgId = (int)request.MessageId;
        Log.Debug($"Info exchange (MobIke handshake) MSG IN: flags={request.MessageFlag.ToString()}, msgId={request.MessageId}, spi_i={request.SpiI:x16}, spi_r={request.SpiR:x16}");

        if (request.Payloads.Count < 1) // other side is saying no change?
        {
            Log.Debug("MobIke handshake with no elements. Other side network unchanged?");
        }

        if (request.MessageFlag.FlagsSet(MessageFlag.Response))
        {
            Log.Warn("Unexpected response in HandleMobIkeHandshake. Will not reply");
            return;
        }

        byte[] messageBytes;
        if (_haveSentMobIkeAddresses)
        {
            messageBytes = BuildSerialMessage(
                ExchangeType.INFORMATIONAL, MessageFlag.Initiator | MessageFlag.Response, sendZeroHeader, _myCrypto, _localSpi, _peerSpi, request.MessageId
            );
        }
        else
        {
            messageBytes = BuildSerialMessage(
                ExchangeType.INFORMATIONAL, MessageFlag.Initiator | MessageFlag.Response, sendZeroHeader, _myCrypto, _localSpi, _peerSpi, request.MessageId,
                new PayloadNotify(IkeProtocolType.NONE, NotifyId.ADDITIONAL_IP4_ADDRESS, null, IpV4Address.FromString(Settings.LocalIpAddress).Value),
                new PayloadNotify(IkeProtocolType.NONE, NotifyId.ADDITIONAL_IP4_ADDRESS, null, IpV4Address.FromString(Settings.LocalTrafficSelector.StartAddress).Value)
            );
            _haveSentMobIkeAddresses = true;
        }

        Log.Debug($"Info exchange (MobIke handshake) MSG OUT. Sending addresses {Settings.LocalIpAddress} and {Settings.LocalTrafficSelector.StartAddress}");
        
        _mobIkeMsgId++;
        Send(to: sender, messageBytes);
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
    /// This is related to <see cref="HandleAuthConfirm"/> and <see cref="HandleSessionReKey"/>
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
            Send(to: sender, BuildResponse(ExchangeType.IKE_AUTH, _peerMsgId, sendZeroHeader, _myCrypto, new PayloadSa(new Proposal())));
            return;
        }

        var childKey = CreateChildKey(IpV4Address.FromEndpoint(sender), chosenChildProposal, _peerNonce, _localNonce, tsi);
        Log.Debug($"    New ESP SPI = {childKey.SpiIn:x8}");
        chosenChildProposal.SpiData = Bit.UInt32ToBytes(childKey.SpiIn); // Used to refer to the child SA in ESP messages?
        chosenChildProposal.SpiSize = 4;

        if (_lastSentMessageBytes is null) throw new Exception("IKE_AUTH stage reached without recording a last sent message? Auth cannot proceed.");

        // pvpn/server.py:301
        var responsePayloadIdr = new PayloadIDr(IdType.ID_IPV4_ADDR, IpV4Address.FromString(Settings.LocalIpAddress).Value, 0, 0); // must be same as ipsec.conf, otherwise auth will fail
        var mySkp = _myCrypto?.SkP;
        if (mySkp is null) throw new Exception("Local SK-p not established before IKE_AUTH received");
        var authData = GeneratePskAuth(_lastSentMessageBytes, _peerNonce, responsePayloadIdr, mySkp, _peerCrypto?.Prf); // I think this is based on the last thing we sent
        Log.Debug($"    Auth data ({authData.Length} bytes) = {Bit.HexString(authData)}");

        Log.Debug($"    Chosen proposal: {Json.Freeze(chosenChildProposal)}");

        // pvpn/server.py:309
        // Send our IKE_AUTH message back
        var response = BuildResponse(ExchangeType.IKE_AUTH, _peerMsgId, sendZeroHeader, _myCrypto,
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
        
        _sessionHost.StatusToString();
        CleanupChildSessions();
        
        // Should now get INFORMATIONAL messages, possibly with some `IKE_DELETE` payloads to tell me about expired sessions.
    }

    /// <summary>
    /// If we have multiple ChildSA open to the same gateway,
    /// remove all but the newest
    /// </summary>
    private void CleanupChildSessions()
    {
        var toRemove = new List<uint>();
        var newest = new Dictionary<IpV4Address, ChildSa>();
        
        // make sure all keys are correct
        foreach (var kvp in _thisSessionChildren)
        {
            kvp.Value.ExternalKey = kvp.Key;
        }

        // filter out any replaced child-sa
        foreach (var kvp in _thisSessionChildren)
        {
            var @this = kvp.Value;
            var gateway = @this.Gateway;
            
            if (newest.ContainsKey(gateway))
            {
                // check which is newest, add the older to the remove list
                var other = newest[gateway];
                if (other.StartTime > @this.StartTime) // other is newer, reject this
                {
                    toRemove.Add(@this.ExternalKey);
                }
                else // this is newer, bump the old one
                {
                    toRemove.Add(other.ExternalKey);
                    newest[gateway] = @this;
                }
            }
            else
            {
                // first seen.
                newest.Add(gateway, @this);
            }
        }
        
        // Kill off any replaced child-sa
        foreach (var key in toRemove)
        {
            var replaced = _thisSessionChildren[key];
            _thisSessionChildren.Remove(key);
            
            EndChildSaWithPeer(replaced);
        }
    }

    /// <summary>
    /// Handle the reply to AUTH message, when we are the initiator.
    /// The remote gateway should already consider us as Established.
    /// Follows from <see cref="HandleSaConfirm"/>
    /// <p></p>
    /// This is related to <see cref="HandleAuth"/> and <see cref="HandleSessionReKey"/>
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

        // Test for some rejection notifications
        var rejection = request.GetPayload<PayloadNotify>(p=>p.NotificationType == NotifyId.TS_UNACCEPTABLE);
        if (rejection is not null)
        {
            Log.Critical("Remote gateway rejected traffic selectors. Check IP and port ranges." +
                         $"\r\nCurrent settings:\r\nLocal:\r\n{Settings.LocalTrafficSelector.Describe()}"+
                         $"\r\nRemote:\r\n{Settings.RemoteTrafficSelector.Describe()}");
            return;
        }
        var noPropMessage = request.GetPayload<PayloadNotify>(pl => pl.NotificationType == NotifyId.NO_PROPOSAL_CHOSEN);
        if (noPropMessage is not null)
        {
            Log.Critical("Peer did not accept any of the ChildSA proposals. Check 'espProposal' in VirtualVpn.VpnSession.HandleSaConfirm");
            return;
        }

        // Read in payloads from peer. If they are all present, we probably have a valid Child SA
        var tsr = request.GetPayload<PayloadTsr>() ?? throw new Exception("IKE_AUTH did not have an TSr payload");
        var idr = request.GetPayload<PayloadIDr>() ?? throw new Exception("IKE_AUTH did not have an IDi payload");
        var auth = request.GetPayload<PayloadAuth>();
        if (auth is null) throw new Exception("Peer requested EAP, which we don't support");

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

        // Generate a new ChildSA with crypto and IP range
        var childKey = CreateChildKey(IpV4Address.FromEndpoint(sender), chosenChildProposal, _peerNonce, _localNonce, tsr);
        Log.Debug($"    New ESP SPI = {childKey.SpiIn:x8}; spi_out={childKey.SpiOut:x8}");
        chosenChildProposal.SpiData = Bit.UInt32ToBytes(childKey.SpiIn); // Used to refer to the child SA in ESP messages?
        chosenChildProposal.SpiSize = 4;

        Log.Debug("    Setting state to established");
        State = SessionState.ESTABLISHED; // Should now have a full Child SA
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
    /// <remarks>
    /// <p>Related to <see cref="IkeCrypto.CreateKeysAndCryptoInstances"/></p>
    /// </remarks>
    private ChildSa CreateChildKey(IpV4Address gateway, Proposal childProposal, byte[] peerNonce, byte[] localNonce, PayloadTsx? trafficSelect)
    {
        // pvpn/server.py:237

        if (_skD is null) throw new Exception("SK-d was not initialised before trying to create a CHILD-SA. Key exchange failed?");
        if (_myCrypto?.Prf is null) throw new Exception("Crypto was not initialised before trying to create a CHILD SA.");
        if (trafficSelect is null) Log.Warn("ChildSA created without traffic selector");

        // Gather up selected protocol, and check all results are valid
        var integId = childProposal.GetTransform(TransformType.INTEG)?.Id;
        if (integId is null) throw new Exception("Chosen proposal has no INTEG section");
        var cipherInfo = childProposal.GetTransform(TransformType.ENCR);
        if (cipherInfo is null) throw new Exception("Chosen proposal has no ENCR section");
        var keyLength = GetKeyLength(cipherInfo);
        if (keyLength is null) throw new Exception("Chosen proposal ENCR section has no KEY_LENGTH attribute");

        // get I/R the right way around
        var nonceI = _weAreInitiator ? localNonce : peerNonce;
        var nonceR = _weAreInitiator ? peerNonce : localNonce;
        
        var seed = nonceI.Concat(nonceR).ToArray();
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


        if (_localSpiOut is null)
        {
            _localSpiOut = new byte[4];
            RandomNumberGenerator.Fill(_localSpiOut);
        }
        var spiOut = Bit.BytesToUInt32(_localSpiOut);

        // The crypto settings are swapped depending on who started the exchanges.
        if (_weAreInitiator) (cryptoIn, cryptoOut) = (cryptoOut, cryptoIn);
        
        var childSa = new ChildSa(gateway, _localSpiOut, childProposal.SpiData, cryptoIn, cryptoOut, _server, this, trafficSelect);

        // '_thisSessionChildren' using spiOut, '_sessionHost' using spiIn.
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
            Id = Settings.StartKeyExchangeFunction
        });

        // Supply a hash function for checksums
        defaultProposal.Transforms.Add(new Transform
        {
            Type = TransformType.INTEG,
            Id = Settings.StartIntegrity
        });

        // Supply a hash function for random number generation
        defaultProposal.Transforms.Add(new Transform
        {
            Type = TransformType.PRF,
            Id = Settings.StartRandomFunction
        });

        _keyExchange ??= BCDiffieHellman.CreateForGroup(DhId.DH_14) ?? throw new Exception("Failed to generate key exchange when generating new session");
        _keyExchange.get_our_public_key(out var newPublicKey);

        _initMessage = BuildSerialMessage(ExchangeType.IKE_SA_INIT, MessageFlag.Initiator, false, null, _localSpi, 0, _myMsgId++,
            new PayloadSa(defaultProposal),
            new PayloadNonce(_localNonce),
            new PayloadKeyExchange((DhId)Settings.StartKeyExchangeFunction, newPublicKey), // Pre-start our preferred exchange
            new PayloadNotify(IkeProtocolType.NONE, NotifyId.NAT_DETECTION_DESTINATION_IP, Array.Empty<byte>(), Bit.RandomBytes(20)),
            new PayloadNotify(IkeProtocolType.NONE, NotifyId.NAT_DETECTION_SOURCE_IP, Array.Empty<byte>(), Bit.RandomBytes(20))
        );

        State = SessionState.IKE_INIT_SENT;
        Log.Debug("Sending initial request for new session");
        Send(to: target, _initMessage);
        // Next should be HandleSaConfirm()
    }

    /// <summary>
    /// We are the initiator, and we got an IKE_SA_INIT message.
    /// We should now check the message is acceptable; and if so, send the first IKE_AUTH message
    /// Follows from <see cref="RequestNewSession"/>
    /// <p></p>
    /// This is closely related to <see cref="HandleSaInit"/>
    /// </summary>
    private void HandleSaConfirm(IkeMessage request, IPEndPoint sender, bool sendZeroHeader) // ike/protocol.py:91
    {
        Log.Debug("        Session: IKE_SA_INIT received (as initiator)");
        Log.Debug("        HandleSaInit():: payloads:", request.DescribeAllPayloads);
        
        _peerNonce ??= request.GetPayload<PayloadNonce>()?.Data;
        
        // Read bits from current settings
        var localAddress = IpV4Address.FromString(Settings.LocalIpAddress);
        var localTrafficSelector = Settings.LocalTrafficSelector.ToSelector();
        var remoteTrafficSelector = Settings.RemoteTrafficSelector.ToSelector();
        
        // Check to see if exactly one SA was chosen
        var saPayload = request.GetPayload<PayloadSa>();

        if (saPayload is null || saPayload.Proposals.Count != 1)
        {
            Log.Warn($"        Session: Peer did not agree with our proposition. Sending rejection to {sender.Address}:{sender.Port}");
            Send(to: sender, message: BuildResponse(ExchangeType.IKE_SA_INIT, _myMsgId, sendZeroHeader, null,
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
            Send(to: sender, message: BuildResponse(ExchangeType.IKE_SA_INIT, _myMsgId, sendZeroHeader, null,
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
        
        var mainIDi = new PayloadIDi(IdType.ID_IPV4_ADDR, localAddress.Value, 0, IpProtocol.ANY);
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
        
        _localSpiOut = new byte[4];
        RandomNumberGenerator.Fill(_localSpiOut);
        Log.Debug($"Supplying ESP SPI as {Bit.BytesToUInt32(_localSpiOut):x8}");
        
        var espProposal = new Proposal
        {
            Number = 1,
            Protocol = IkeProtocolType.ESP,
            SpiData = _localSpiOut,
            Transforms = {
                new Transform
                {// M-Pesa requests AES_CBC_256/HMAC_SHA1_96
                    Type = TransformType.ENCR,
                    Id = (uint)EncryptionTypeId.ENCR_AES_CBC,
                    Attributes = { new TransformAttribute(TransformAttr.KEY_LENGTH, 256) }
                },
                new Transform
                {
                    Type = TransformType.INTEG,
                    Id = Settings.StartIntegrity
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
        Log.Trace("Building HandleSaConfirm confirmation message, switching to port 4500");
        var msgBytes = BuildSerialMessage(ExchangeType.IKE_AUTH, MessageFlag.Initiator,
            sendZeroHeader:true, // 'true' if we are switching to 4500
            _myCrypto, _localSpi, _peerSpi, _myMsgId++,
            
            mainIDi,
            new PayloadNotify(IkeProtocolType.NONE, NotifyId.INITIAL_CONTACT, null, null),
            peerIDr,
            new PayloadAuth(AuthMethod.PSK, pskAuth),
            new PayloadSa(espProposal),
            new PayloadTsi(localTrafficSelector), // our address ranges,
            new PayloadTsr(remoteTrafficSelector), // expected ranges on their side
            
            new PayloadNotify(IkeProtocolType.NONE, NotifyId.ADDITIONAL_IP4_ADDRESS, null, localTrafficSelector.StartAddress),
            
            new PayloadNotify(IkeProtocolType.NONE, NotifyId.MOBIKE_SUPPORTED, null, null) // Enable mobility extensions
            // Notifications for extra IP addresses could go here, but we don't support them yet.
        );
        
        // The message should be something that VirtualVpn.Crypto.IkeCrypto.VerifyChecksumInternal would give the OK to
        var ok = _myCrypto!.VerifyChecksum(msgBytes.Skip(4).ToArray());
        if (!ok) Log.Warn("Message did not pass our own checksum. Likely to be rejected by peer.");
        
        // Switch to 4500 port now. The protocol works without it, but VirtualVPN assumes the switch will happen.
        // See https://docs.strongswan.org/docs/5.9/features/mobike.html
        Log.Trace("Sending IKE_AUTH message");
        Send(to: new IPEndPoint(sender.Address, port:4500), message: msgBytes);
        State = SessionState.AUTH_SENT;
        // Next is HandleAuthConfirm()
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
            Send(to: sender, message: BuildResponse(ExchangeType.IKE_SA_INIT, _peerMsgId, sendZeroHeader, null,
                new PayloadNotify(IkeProtocolType.IKE, NotifyId.INVALID_KE_PAYLOAD, null, null)
            ));
            return;
        }

        // If we can agree on a proposition, but the initiator's default is not acceptable,
        // then we will make a new proposal with a new key exchange.
        if ((uint)payloadKe.DiffieHellmanGroup != preferredDiffieHellman.Value)
        {
            Log.Info("        Session: We agree on a viable proposition, but it was not the default. Requesting switch.");

            var reKeyMessage = BuildResponse(ExchangeType.IKE_SA_INIT, _peerMsgId, sendZeroHeader, null,
                new PayloadSa(chosenProposal),
                new PayloadNotify(IkeProtocolType.IKE, NotifyId.INVALID_KE_PAYLOAD, Bit.UInt64ToBytes(request.SpiI), Bit.UInt16ToBytes((ushort)DhId.DH_14))
            );

            Send(to: sender, message: reKeyMessage);
            //_peerMsgId--; // this is not going to count as a sequenced message
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

        var saMessage = BuildResponse(ExchangeType.IKE_SA_INIT, _peerMsgId, sendZeroHeader, null,
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
        _outgoingMessageCount++;
        _lastContact = to;
        _lastSentMessageBytes = message;
        Log.Trace($"Message outgoing. {message.Length} bytes to {to.Address}:{to.Port}");
        _server.SendRaw(message, to);

        if (Settings.CaptureTraffic && Log.IsTracing)
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

    public void UpdateTrafficTimeout()
    {
        LastTouchTimer.Restart();
    }

    /// <summary>
    /// Returns true if this sessions is in a starting-up state.
    /// Returns false if it is established, stopped, or stopping.
    /// </summary>
    public bool IsStarting()
    {
        switch (State)
        {
            case SessionState.INITIAL:
            case SessionState.IKE_INIT_SENT:
            case SessionState.SA_SENT:
            case SessionState.CHILD_SA_SENT:
            case SessionState.AUTH_SENT:
                return true;
                
            case SessionState.ESTABLISHED:
            case SessionState.DELETED:
            case SessionState.KE_SENT:
            case SessionState.HASH_SENT:
            case SessionState.AUTH_SET:
            case SessionState.CONF_SENT:
                return false;
            
            default:
                throw new ArgumentOutOfRangeException();
        }
    }

    /// <summary>
    /// Human readable description of the session
    /// </summary>
    public string Describe()
    {
        var cryptState = _peerCrypto is null ? "no cipher" : "cipher established";
        return $"Session to {Gateway.AsString} since {_startDateTime:yyyy-MM-dd HH:mm:ss} {cryptState}; State={State.ToString()}; IKE message count in={_incomingMessageCount}, out={_outgoingMessageCount};";
    }

    public IEnumerable<ChildSa> ChildSessions() => _thisSessionChildren.Values.ToArray();

    
    /// <summary>
    /// Notify the Session that a connection was terminated at an unexpected point.
    /// This is part of the <see cref="VpnServer.AlarmIsActive"/> system.
    /// </summary>
    public void ConnectionRemoteTerminated(IpV4Address gateway) => _sessionHost.ConnectionRemoteTerminated(gateway);

    /// <summary>
    /// Notify the Session that a connection was fully established in a normal way.
    /// This is part of the <see cref="VpnServer.AlarmIsActive"/> system.
    /// </summary>
    public void ConnectionNormal() => _sessionHost.ConnectionNormal();

    /// <summary>
    /// Informs the VPN server that a keep-alive was just sent to the target gateway
    /// </summary>
    public void SetLastKeepAlive(IpV4Address gateway)
    {
        _sessionHost.SetLastKeepAlive(gateway);
    }
}
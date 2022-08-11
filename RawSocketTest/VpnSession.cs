using System.Net;
using System.Security.Cryptography;
using System.Text;
using RawSocketTest.Crypto;
using RawSocketTest.gmpDh;
using RawSocketTest.Helpers;
using RawSocketTest.Payloads;
using RawSocketTest.Payloads.PayloadSubunits;
using SkinnyJson;

namespace RawSocketTest;

/// <summary>
/// Negotiates and handles a single VPN session between self and one peer
/// </summary>
internal class VpnSession
{
    //## State machine vars ##//
    
    private SessionState _state;
    
    /// <summary>sequence number for receiving</summary>
    private long _maxSeq = -1;
    /// <summary>sequence number for sending</summary>
    private readonly long _seqOut;
    
    private long _peerMsgId;
    private byte[]? _lastMessageBytes;
    private byte[]? _peerNonce;
    private byte[]? _skD;
    
    //## Algorithmic selections (negotiated with peer) ##//
    
    private IkeCrypto? _myCrypto;
    private IkeCrypto? _peerCrypto;
    
    //## Locked for session ##//
    
    private readonly UdpServer _server; // note: should increment _seqOut when sending
    private readonly VpnServer _sessionHost;
    private readonly ulong _peerSpi;
    private readonly ulong _localSpi;
    private readonly byte[] _localNonce;
    private readonly List<ChildSa> _thisSessionChildren = new();
    private byte[]? _previousRequestRawData;

    public VpnSession(UdpServer server, VpnServer sessionHost, ulong peerSpi)
    {
        // pvpn/server.py:208
        _server = server;
        _sessionHost = sessionHost;
        _peerSpi = peerSpi;
        LastTouchUtc = DateTime.UtcNow;
        _localSpi = Bit.RandomSpi();
        _localNonce = Bit.RandomNonce();
        _state = SessionState.INITIAL;
        _seqOut = 0;
        _peerMsgId = 0;
    }

    public DateTime LastTouchUtc { get; set; }
    public TimeSpan AgeNow => DateTime.UtcNow - LastTouchUtc;


    /// <summary>
    /// Do any shut-down stuff
    /// </summary>
    public void Close() { }

    /// <summary>
    /// Returns true if the given sequence is less-or-equal to the largest we've seen before
    /// </summary>
    public bool OutOfSequence(uint seq) => seq <= _maxSeq;

    /// <summary>
    /// Needs crypto, and some corrections. See pvpn/server.py:411
    /// </summary>
    public bool VerifyMessage(byte[] data)
    {
        // the session should have a cryptography method selected
        if (_peerCrypto is null) throw new Exception("No incoming crypto method agreed");
        
        return _peerCrypto.VerifyChecksum(data);
    }

    /// <summary>
    /// See pvpn/server.py:416
    /// </summary>
    public void IncrementSequence(uint seq)
    {
        if (seq > (_maxSeq+65536)) _maxSeq++;
        else if (seq == _maxSeq) _maxSeq++;
        else _maxSeq = seq; // this isn't exactly right, see pvpn/server.py:421
    }

    // pvpn/server.py:253
    private byte[] BuildResponse(ExchangeType exchange, bool sendZeroHeader, IkeCrypto? crypto, params MessagePayload[] payloads)
    {
        var resp = new IkeMessage
        {
            Exchange = exchange,
            SpiI = _peerSpi,
            SpiR = _localSpi,
            MessageFlag = MessageFlag.Response,
            MessageId = (uint)_peerMsgId,
            Version = IkeVersion.IkeV2,
        };
        resp.Payloads.AddRange(payloads);
        
        return resp.ToBytes(sendZeroHeader, crypto); // should wrap payloads in PayloadSK if we have crypto
    }

    /// <summary>
    /// Handle an incoming key exchange message
    /// </summary>
    public void HandleIke(IkeMessage request, IPEndPoint sender, bool sendZeroHeader)
    {
        try
        {
            HandleIkeInternal(request, sender, sendZeroHeader);
            _peerMsgId++;
            
            _previousRequestRawData = request.RawData; // needed to do PSK auth
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to handle IKE message. Error: {ex}");
        }
    }

    private void HandleIkeInternal(IkeMessage request, IPEndPoint sender, bool sendZeroHeader)
    {
        // pvpn/server.py:260
        LastTouchUtc = DateTime.UtcNow;

        // Check for peer requesting a repeat of last message
        if (request.MessageId == _peerMsgId - 1) 
        {
            if (_lastMessageBytes is null)
            {
                Console.WriteLine("Asked to repeat a message we didn't send? This session has faulted");
                // TODO: kill the session? respond with a failure message?
                return;
            }

            _server.SendRaw(_lastMessageBytes, sender, out _); // don't add zero pad again?
            return;
        }

        // make sure we're in sequence
        if (request.MessageId != _peerMsgId)
        {
            Console.WriteLine($"Request is out of sequence. Expected {_peerMsgId}, but got {request.MessageId}. Ignoring.");
            return;
        }

        if (request.Exchange == ExchangeType.IKE_AUTH)
        {
            File.WriteAllText(@"C:\temp\zzzFullIkeAuth.txt", Bit.Describe("Full message", request.RawData));
        }

        //if (_myCrypto is not null) Console.WriteLine($"This session has Crypto.\r\n  Me-> {_myCrypto}\r\nThem-> {_peerCrypto}\r\n");
        
        // We should have crypto now, as long as we're out of IKE_SA_INIT phase
        request.ReadPayloadChain(_peerCrypto); // pvpn/server.py:266

        switch (request.Exchange)
        {
            case ExchangeType.IKE_SA_INIT: // pvpn/server.py:268
                AssertState(SessionState.INITIAL, request);
                HandleSaInit(request, sender, sendZeroHeader);
                break;

            case ExchangeType.IKE_AUTH: // pvpn/server.py:287
                AssertState(SessionState.SA_SENT, request);
                Console.WriteLine("IKE_AUTH received");
                HandleAuth(request, sender, sendZeroHeader);
                //Console.WriteLine($"This session has Crypto.\r\n  Me-> {_myCrypto}\r\nThem-> {_peerCrypto}\r\n");
                //Console.WriteLine(Json.Beautify(Json.Freeze(request)));
                break;

            case ExchangeType.INFORMATIONAL: // pvpn/server.py:315
                Console.WriteLine("INFORMATIONAL received");
                break;

            case ExchangeType.CREATE_CHILD_SA: // pvpn/server.py:340
                Console.WriteLine("CREATE_CHILD_SA received");
                break;

            
            default:
               throw new Exception($"Unexpected request: {request.Exchange.ToString()}");
        }
    }

    private void HandleAuth(IkeMessage request, IPEndPoint sender, bool sendZeroHeader)
    {
        Console.WriteLine("        HandleAuth():: payloads:");
        foreach (var payload in request.Payloads) Console.WriteLine($"            {payload.Describe()}");

        var peerSkp = _peerCrypto?.SkP;
        if (peerSkp is null) throw new Exception("Peer SK-p not established before IKE_AUTH received");
        if (_peerNonce is null) throw new Exception("Peer N-once was not established before IKE_AUTH received");
        if (_previousRequestRawData is null) throw new Exception("Peer's previous raw request not stored during IKE_INIT_SA to use in IKE_AUTH");
        
        // read traffic selectors
        var tsi = request.GetPayload<PayloadTsi>()?? throw new Exception("IKE_AUTH did not have an Traffic Select initiator payload");
        var tsr = request.GetPayload<PayloadTsr>()?? throw new Exception("IKE_AUTH did not have an Traffic Select responder payload");
        
        var sa = request.GetPayload<PayloadSa>() ?? throw new Exception("IKE_AUTH did not have an SA payload");
        var idi = request.GetPayload<PayloadIDi>() ?? throw new Exception("IKE_AUTH did not have an IDi payload");
        var auth = request.GetPayload<PayloadAuth>();
        if (auth is null) throw new Exception("Peer requested EAP, which we don't support");
        
        var pskAuth = GeneratePskAuth(_previousRequestRawData, _localNonce, idi, peerSkp);
        if (Bit.AreDifferent(pskAuth, auth.AuthData))
        {
            throw new Exception("PSK auth failed: initiator's hash did not match our expectations.\r\n\t" +
                                $"Expected {Bit.HexString(pskAuth)},\r\n\tbut got {Bit.HexString(auth.AuthData)}");
        }
        Console.WriteLine("    PSK auth agreed from this side");
        
        // pvpn/server.py:298
        var chosenChildSa = sa.GetProposalFor(EncryptionTypeId.ENCR_AES_CBC);
        if (chosenChildSa is null)
        {
            Console.WriteLine("    FATAL: could not find a compatible Child SA");
            // TODO: how do we reject?
            return;
        }
        
        var childKey = CreateChildKey(chosenChildSa, _peerNonce, _localNonce);
        chosenChildSa.SpiData = Bit.UInt32ToBytes(childKey.SpiIn); // Used to refer to the child SA in ESP messages?
        chosenChildSa.SpiSize = 4;
        
        if (_lastMessageBytes is null) throw new Exception("IKE_AUTH stage reached without recording a last sent message? Auth cannot proceed.");
        
        // pvpn/server.py:301
        var responsePayloadIdr = new PayloadIDr(IdType.ID_FQDN, Encoding.ASCII.GetBytes("V_VPN-0_1"), 0, 0);
        var mySkp = _myCrypto?.SkP;
        if (mySkp is null) throw new Exception("Local SK-p not established before IKE_AUTH received");
        var authData = GeneratePskAuth(_lastMessageBytes, _peerNonce, responsePayloadIdr, mySkp); // I think this is based on the last thing we sent
        
        // pvpn/server.py:309
        // Send our Child-SA message back
        var response = BuildResponse(ExchangeType.IKE_AUTH, sendZeroHeader, _myCrypto, 
            new PayloadSa(chosenChildSa),
            tsi, tsr, // just accept whatever traffic selectors. We're virtual.
            responsePayloadIdr,
            new PayloadAuth(AuthMethod.PSK, authData)
        );
        // todo: above will break because we haven't done the crypto stuff yet. See pvpn/message.py:555
        
        // deliberately ignoring 'CP' for now
        
        // Send reply.
        Reply(to: sender, response);
        
        _state = SessionState.ESTABLISHED; // Should now have a full Child SA
    }

    /// <summary>
    /// PSK auth that matches what StrongSwan seems to do
    /// See src/libcharon/sa/ikev2/keymat_v2.c:659
    /// </summary>
    private byte[] GeneratePskAuth(byte[] messageData, byte[] nonce, PayloadIDx payload, byte[] skP)
    {
        var prf = _peerCrypto?.Prf;
        if (prf is null) throw new Exception("Tried to generate PSK auth before key exchange completed");
        
        // 01 -> some kind of type? IdType.ID_IPV4_ADDR == 01 AuthId_1.PSK == 01     <-- guessing IdType.ID_IPV4_ADDR, as this goes with the data
        // 3 zero bytes,
        // 9F 45 0D 7E -> 159.69.13.126 ... this is the initiator's IP address
            
        // IDx' seems to be fairly constant:       01 00 00 00 9F 45 0D 7E
        // IDx' => 8 bytes @ 0x7f9b1fee7850        01 00 00 00 9F 45 0D 7E    <-- this is not nonce, it's something else
        // SK_p => 32 bytes @ 0x7f9af4007340       AF E8 1D 52 00 28 34 E6 2C 70 58 9B C2 D8 5F 1A B6 01 F2 05 EB 44 B1 BC 1A 66 B9 65 76 D4 6F DD

        // octets = message + nonce + prf(Sk_px, IDx')
        // AUTH = prf(prf(secret, keypad), octets)
        
        Console.WriteLine($"PSK message: {payload.Describe()}");
        
        // IEB: temporarily hard coding. Debug and find the data we need

        var prefix = new byte[] { (byte)payload.IdType, 0, 0, 0 };//new byte[] { (byte)IdType.ID_IPV4_ADDR, 0, 0, 0 };
        var peerId = payload.IdData; //new byte[] { 0x9F, 0x45, 0x0D, 0x7E };
        var idxTick = prefix.Concat(peerId).ToArray();
        var octetPad = prf.Hash(skP, idxTick);
        
        var bulk = messageData.Concat(nonce).Concat(octetPad).ToArray();
        
        Console.WriteLine($"#### {Bit.Describe("IDx'", idxTick)}");
        Console.WriteLine($"#### {Bit.Describe("SK_p", skP)}");
        Console.WriteLine($"#### {Bit.Describe("prf(Sk_px, IDx')", octetPad)}");
        Console.WriteLine($"#### {Bit.Describe("octets =  message + nonce + prf(Sk_px, IDx') ", messageData)}"); // expect ~ 1192 bytes
        
        
        var psk = Encoding.ASCII.GetBytes("ThisIsForTestOnlyDontUse");
        var pad = Encoding.ASCII.GetBytes(Prf.IKEv2_KeyPad);
        var prfPskPad = prf.Hash(psk, pad);
        
        
        return prf.Hash(prfPskPad, bulk);
    }

    private ChildSa CreateChildKey(Proposal childProposal, byte[] peerNonce, byte[] localNonce)
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
        
        var totalSize = 2*check.KeySize + 2*cipher.KeySize;
        var keySource = _myCrypto.Prf.PrfPlus(_skD, seed, totalSize);
        
        var idx = 0;
        var skEi = Bit.Subset(cipher.KeySize, keySource, ref idx);
        var skAi = Bit.Subset(check.KeySize, keySource, ref idx);
        var skEr = Bit.Subset(cipher.KeySize, keySource, ref idx);
        var skAr = Bit.Subset(check.KeySize, keySource, ref idx);
        
        var cryptoIn = new IkeCrypto(cipher, check, null, skEi, skAi, null, null);
        var cryptoOut = new IkeCrypto(cipher, check, null, skEr, skAr, null, null);
        
        
        //self.child_sa.append(child_sa)
        //self.sessions[child_sa.spi_in] = child_sa

        byte[] randomSpi = new byte[4];
        RandomNumberGenerator.Fill(randomSpi);
        
        var childSa = new ChildSa(randomSpi, childProposal.SpiData, cryptoIn, cryptoOut);
        
        _sessionHost.AddChildSession(childSa); // this gets us the 32-bit SA used for ESA, not the 64-bit used for key exchange
        _thisSessionChildren.Add(childSa);
        
        return childSa;
    }

    /// <summary>
    /// Not yet implemented. Call out to an external server, try to start an IKE/SA session
    /// </summary>
    /// <param name="target"></param>
    public void RequestNewSession(IPEndPoint target)
    {
        // this is pretty much what we'll have to do to start a session.
        Proposal defaultProposal = new Proposal(); // TODO: fill this in
        byte[] newPublicKey = new byte[256]; // todo: generate
        
        var reKeyMessage = BuildResponse(ExchangeType.IKE_SA_INIT, false, null,
            new PayloadSa(defaultProposal),
            new PayloadNonce(_localNonce),
            new PayloadKeyExchange(DhId.DH_14, newPublicKey), // Pre-start our preferred exchange
            new PayloadNotify(IkeProtocolType.NONE, NotifyId.NAT_DETECTION_DESTINATION_IP, Array.Empty<byte>(), Bit.RandomBytes(20)),
            new PayloadNotify(IkeProtocolType.NONE, NotifyId.NAT_DETECTION_SOURCE_IP, Array.Empty<byte>(), Bit.RandomBytes(20))
        );
        
        // todo: send the message
    }

    private void HandleSaInit(IkeMessage request, IPEndPoint sender, bool sendZeroHeader)
    {
        Console.WriteLine("        Session: IKE_SA_INIT received");
        Console.WriteLine("        HandleSaInit():: payloads:");
        foreach (var payload in request.Payloads) Console.WriteLine($"            {payload.Describe()}");

        _peerNonce = request.GetPayload<PayloadNonce>()?.Data;

        // pick a proposal we can work with, if any
        var saPayload = request.GetPayload<PayloadSa>();
        if (saPayload is null) throw new Exception("IKE_SA_INIT did not contain any SA proposals");

        var chosenProposal = saPayload.GetProposalFor(EncryptionTypeId.ENCR_AES_CBC); // we only support AES CBC mode at the moment, and M-Pesa only does DH-14
        var payloadKe = request.GetPayload<PayloadKeyExchange>();
        
        var preferredDiffieHellman = chosenProposal?.GetTransform(TransformType.DH)?.Id;

        // If there is nothing we can agree on, this session is dead. Send an error message
        if (chosenProposal is null || payloadKe is null || preferredDiffieHellman is null ||  payloadKe.KeyData.Length < 1)
        {
            // pvpn/server.py:274
            Console.WriteLine($"        Session: Could not find an agreeable proposition. Sending rejection to {sender.Address}:{sender.Port}");
            Reply(to: sender, message: BuildResponse(ExchangeType.IKE_SA_INIT, sendZeroHeader, null,
                new PayloadNotify(IkeProtocolType.IKE, NotifyId.INVALID_KE_PAYLOAD, null, null)
            ));
            return;
        }
        
        // If we can agree on a proposition, but the initiator's default is not acceptable,
        // then we will make a new proposal with a new key exchange.
        if ((uint)payloadKe.DiffieHellmanGroup != preferredDiffieHellman.Value)
        {
            Console.WriteLine("        Session: We agree on a viable proposition, but it was not the default. Requesting switch.");
            
            var reKeyMessage = BuildResponse(ExchangeType.IKE_SA_INIT, sendZeroHeader, null,
                new PayloadSa(chosenProposal),
                new PayloadNotify(IkeProtocolType.IKE, NotifyId.INVALID_KE_PAYLOAD, Bit.UInt64ToBytes(request.SpiI), Bit.UInt16ToBytes((ushort)DhId.DH_14))
            );
            
            Reply(to: sender, message: reKeyMessage);
            _peerMsgId--; // this is not going to count as a sequenced message
            return;
        }

        // build key
        Console.WriteLine($"        Session: We agree on a viable proposition, and it is the default. Continue with key share for {payloadKe.DiffieHellmanGroup.ToString()}" +
                          $" Supplied length is {payloadKe.KeyData.Length} bytes");

        var gmpDh = GmpDiffieHellman.gmp_diffie_hellman_create(DhId.DH_14) ?? throw new Exception($"Failed to create key exchange for group {payloadKe.DiffieHellmanGroup.ToString()}");
        gmpDh.set_their_public_key(payloadKe.KeyData);
        gmpDh.get_our_public_key(out var publicKey);
        gmpDh.get_shared_secret(out var secret);
        
        // create keys from exchange result. If something went wrong, we will end up with a checksum failure
        CreateKeyAndCrypto(chosenProposal, secret, null);
        
        var saMessage = BuildResponse(ExchangeType.IKE_SA_INIT, sendZeroHeader, null,
            new PayloadSa(chosenProposal),
            new PayloadNonce(_localNonce),
            new PayloadKeyExchange(payloadKe.DiffieHellmanGroup, publicKey),
            new PayloadNotify(IkeProtocolType.NONE, NotifyId.NAT_DETECTION_DESTINATION_IP, Array.Empty<byte>(), Bit.RandomBytes(20)),
            new PayloadNotify(IkeProtocolType.NONE, NotifyId.NAT_DETECTION_SOURCE_IP, Array.Empty<byte>(), Bit.RandomBytes(20))
        );

        Console.WriteLine($"        Session: Sending IKE_SA_INIT reply to {sender.Address}:{sender.Port}");
        Reply(to: sender, message: saMessage);
        _state = SessionState.SA_SENT;

        Console.WriteLine("        Session: Completed IKE_SA_INIT, transition to state=SA_SENT");
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
        return info.Attributes.FirstOrDefault(a=>a.Type == TransformAttr.KEY_LENGTH)?.Value;
    }

    private void Reply(IPEndPoint to, byte[] message)
    {
        _lastMessageBytes = message;
        _server.SendRaw(message, to, out _);
        
        var name = @$"C:\temp\IKEv2-Reply_{_maxSeq}_Port-{to.Port}_IKE.bin";
        File.WriteAllBytes(name, message);
    }

    /// <summary>
    /// Throw an exception if we're not in the expected state.
    /// Otherwise do nothing
    /// </summary>
    private void AssertState(SessionState expected, IkeMessage ikeMessage)
    {
        if (_state != expected)
        {
            Console.WriteLine(Json.Freeze(ikeMessage));
            throw new Exception($"Expected to be in state {expected.ToString()}, but was in {_state.ToString()}");
        }

        Console.WriteLine($"        Session: State correct: {_state.ToString()} = {expected.ToString()}");
    }

    /// <summary>
    /// Handle an incoming SPE message
    /// </summary>
    public void HandleSpe(byte[] data, IPEndPoint sender)
    {
        // the session should have a cryptography method selected
        if (_myCrypto is null) throw new Exception("No incoming crypto method agreed");
        
        // IEB: pretty sure the 'nextHeader' thing is wrong here. Find in RFCs
        var rawMessage = _myCrypto.Decrypt(data, out var nextHeader);

        var header = (IpProtocol)nextHeader;
        switch (header)
        {
            case IpProtocol.IPV4:
                // pvpn/ip.py:402
                // TODO: parse IPv4 packet
                // IEB: I guess we want to run a TCP stack (client) here, and connect it to our child app?
                Console.WriteLine($"IPv4 message (not yet handled) {rawMessage.Length} bytes, sender={sender.Address}:{sender.Port}");
                break;

            case IpProtocol.UDP:
                // TODO: parse UDP packet
                Console.WriteLine($"UPD message (not yet handled) {rawMessage.Length} bytes, sender={sender.Address}:{sender.Port}");
                break;

            case IpProtocol.ANY:
            case IpProtocol.ICMP:
            case IpProtocol.IGMP:
            case IpProtocol.GGP:
            case IpProtocol.TCP:
            case IpProtocol.RDP:
            case IpProtocol.IPV6:
            case IpProtocol.ESP:
            case IpProtocol.ICMPV6:
            case IpProtocol.MH:
            case IpProtocol.RAW:
                Console.WriteLine($"{nextHeader.ToString()} message (not supported) sender={sender.Address}:{sender.Port}");
                break;
            
            default:
                throw new ArgumentOutOfRangeException();
        }

    }
}
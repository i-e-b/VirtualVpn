using System.Net;
using RawSocketTest.Crypto;
using RawSocketTest.Helpers;
using RawSocketTest.Payloads;
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
    private readonly ulong _peerSpi;
    private readonly ulong _localSpi;
    private readonly byte[] _localNonce;

    public VpnSession(UdpServer server, ulong peerSpi)
    {
        // pvpn/server.py:208
        _server = server;
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

        // We should have crypto now, as long as we're out of IKE_SA_INIT phase
        //request.ReadPayloadChain(_peerCrypto); // pvpn/server.py:266
        request.ReadPayloadChain(_myCrypto); // pvpn/server.py:266

        switch (request.Exchange)
        {
            case ExchangeType.IKE_SA_INIT: // pvpn/server.py:268
                AssertState(SessionState.INITIAL, request);
                HandleSaInit(request, sender, sendZeroHeader);
                break;

            case ExchangeType.IKE_AUTH: // pvpn/server.py:287
                AssertState(SessionState.SA_SENT, request);
                Console.WriteLine("IKE_AUTH received");
                Console.WriteLine($"This session has Crypto.\r\n  Me-> {_myCrypto}\r\nThem-> {_peerCrypto}\r\n");
                Console.WriteLine(Json.Beautify(Json.Freeze(request)));
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

    // TODO: replace with random for the session
    private static readonly byte[] _publicFix =
    {
        0x08, 0x5D, 0xE0, 0x94, 0x6B, 0xBE, 0xAB, 0x4A, 0x74, 0x7E, 0x87, 0x5C, 0x3D, 0x0F, 0xFD, 0x70,
        0xEA, 0x00, 0x9C, 0x01, 0x5A, 0x0D, 0xE6, 0x00, 0x5B, 0xCE, 0xF3, 0x31, 0x1B, 0x50, 0x6C, 0x22,
        /*0xE8, 0x13, 0xE7, 0x6D, 0x65, 0x19, 0xDA, 0x7C, 0x34, 0xF1, 0xEA, 0x80, 0x52, 0x94, 0xB7, 0x93,
        0x47, 0xB3, 0xB9, 0x24, 0x3D, 0xDC, 0xDE, 0x70, 0x74, 0xCB, 0x95, 0xC1, 0x50, 0x5C, 0x2F, 0x53,
        0x58, 0x88, 0x62, 0xB9, 0xC7, 0x18, 0xC3, 0xBA, 0x72, 0x1F, 0x37, 0x7C, 0x7D, 0xBC, 0x00, 0x42,
        0x67, 0x87, 0xBF, 0x72, 0x7C, 0x40, 0x23, 0x19, 0xBB, 0xAD, 0x17, 0xF1, 0x19, 0xCF, 0xC7, 0xC0,
        0x38, 0x82, 0xF6, 0xF2, 0x7E, 0x33, 0x9F, 0x74, 0xDD, 0x36, 0x07, 0xB3, 0x70, 0xFF, 0xF4, 0xB4,
        0xF9, 0xCC, 0xD8, 0x84, 0x01, 0x80, 0xAC, 0xFA, 0xD0, 0x99, 0xAE, 0x32, 0xEC, 0x7C, 0x10, 0x8D,
        0xE8, 0xB3, 0xB1, 0xC0, 0xEE, 0xA5, 0xE9, 0x3D, 0x45, 0xCE, 0x58, 0xD0, 0xA6, 0xB5, 0xB6, 0x54,
        0x37, 0x38, 0xB8, 0x55, 0x2D, 0x8B, 0xC5, 0x75, 0x83, 0x9D, 0x21, 0x91, 0x4E, 0x8A, 0x02, 0x26,
        0x1B, 0xA7, 0x33, 0x00, 0xEB, 0xB5, 0x2F, 0xE5, 0x28, 0xF8, 0x50, 0x66, 0x1E, 0xAE, 0x5A, 0xDC,
        0xDE, 0x1F, 0x0B, 0x20, 0xD4, 0xA4, 0x13, 0x1F, 0x71, 0xD0, 0x2C, 0x1F, 0xA6, 0x8C, 0xBD, 0x4A,
        0x1E, 0x1D, 0x4E, 0xF8, 0x91, 0x31, 0x3E, 0x14, 0x2D, 0x3C, 0xC7, 0x28, 0x8C, 0xCB, 0x7F, 0xF4,
        0x9F, 0x85, 0xB4, 0xDA, 0x0E, 0x81, 0x32, 0x71, 0x7D, 0x8C, 0xFF, 0x27, 0x0E, 0x1E, 0x97, 0x44,
        0x7D, 0xC4, 0x57, 0xE6, 0x49, 0xB8, 0x92, 0xD1, 0xED, 0xE3, 0x68, 0xE2, 0x4C, 0xDB, 0x02, 0x23,
        0xC4, 0x89, 0x03, 0xFD, 0xC8, 0x69, 0xD5, 0x94, 0x11, 0x25, 0x55, 0x65, 0x68, 0x78, 0x23, 0x7F*/
    };

    public void TriggerSession()
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
        
        DHKeyExchange.DiffieHellman(payloadKe.DiffieHellmanGroup, payloadKe.KeyData /*Them public*/, out var publicKey, out var sharedSecret);
        CreateKeyAndCrypto(chosenProposal, sharedSecret, publicKey, null, payloadKe.KeyData);

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
    private void CreateKeyAndCrypto(Proposal proposal, byte[] sharedSecret, byte[] publicKey, byte[]? oldSkD, byte[] payloadKeData)
    {
        // pvpn/server.py:223
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
        
        // Build protocols
        var prf = new Prf((PrfId)prfId);
        var integ = new Integrity((IntegId)integId);
        var cipher = new Cipher((EncryptionTypeId)cipherInfo.Id, keyLength.Value);
        
        byte[] sKeySeed;
        if (oldSkD is null)
        {
            sKeySeed = prf.Hash(_peerNonce.Concat(_localNonce).ToArray(), sharedSecret);
        }
        else
        {
            sKeySeed = prf.Hash(oldSkD, sharedSecret.Concat(_peerNonce).Concat(_localNonce).ToArray());
        }
        
        // Generate crypto bases
        
        var totalSize = 3*prf.KeySize + 2*integ.KeySize + 2*cipher.KeySize;
        var seed = _peerNonce.Concat(_localNonce).Concat(Bit.UInt64ToBytes(_peerSpi)).Concat(Bit.UInt64ToBytes(_localSpi)).ToArray();
        var keySource = prf.PrfPlus(sKeySeed, seed, totalSize);
        
        var idx = 0;
        _skD = Bit.Subset(prf.KeySize, keySource, ref idx);
        var skAi = Bit.Subset(integ.KeySize, keySource, ref idx);
        var skAr = Bit.Subset(integ.KeySize, keySource, ref idx);
        var skEi = Bit.Subset(cipher.KeySize, keySource, ref idx);
        var skEr = Bit.Subset(cipher.KeySize, keySource, ref idx);
        var skPi = Bit.Subset(prf.KeySize, keySource, ref idx);
        var skPr = Bit.Subset(prf.KeySize, keySource, ref idx);
        
        if (idx != keySource.Length) throw new Exception($"Unexpected key set length in {nameof(CreateKeyAndCrypto)}. Expected {keySource.Length} but got {idx}");
        
        // build crypto for both sides
        _myCrypto = new IkeCrypto(cipher, integ, prf, skEr, skAr, skPr, null);
        _peerCrypto = new IkeCrypto(cipher, integ, prf, skEi, skAi, skPi, null);
        
        File.WriteAllText(@"C:\temp\zzzLastSessionKeys.txt",
            Bit.Describe("SK d", _skD)+
            Bit.Describe("skAi", skAi)+
            Bit.Describe("skAr", skAr)+
            Bit.Describe("skEi", skEi)+
            Bit.Describe("skEr", skEr)+
            Bit.Describe("skPi", skPi)+
            Bit.Describe("skPr", skPr)+
            Bit.Describe("keySource", keySource)+
            Bit.Describe("seed", seed)+
            Bit.Describe("secret", sharedSecret)+
            Bit.Describe("sKeySeed", sKeySeed)+
            Bit.Describe("publicKey", publicKey)+
            Bit.Describe("payloadKe", payloadKeData)
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
        
        var rawMessage = _myCrypto.Decrypt(data, out var nextHeader);

        switch (nextHeader)
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
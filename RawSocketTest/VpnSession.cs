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
    
    private static readonly byte[] _publicFix = {
        0x08, 0x5D, 0xE0, 0x94, 0x6B, 0xBE, 0xAB, 0x4A, 0x74, 0x7E, 0x87, 0x5C, 0x3D, 0x0F, 0xFD, 0x70,
        0xEA, 0x00, 0x9C, 0x01, 0x5A, 0x0D, 0xE6, 0x00, 0x5B, 0xCE, 0xF3, 0x31, 0x1B, 0x50, 0x6C, 0x22
    };

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
            Console.WriteLine($"        Session: We agree on a viable proposition, but it was not the default. Sending a new key exchange set");
            
            var reKeyMessage = BuildResponse(ExchangeType.IKE_SA_INIT, sendZeroHeader, null,
                new PayloadSa(chosenProposal),
                new PayloadNonce(_localNonce),
                new PayloadKeyExchange((DhId)preferredDiffieHellman.Value, _publicFix),
                new PayloadNotify(IkeProtocolType.NONE, NotifyId.NAT_DETECTION_DESTINATION_IP, Array.Empty<byte>(), Bit.RandomBytes(20)),
                new PayloadNotify(IkeProtocolType.NONE, NotifyId.NAT_DETECTION_SOURCE_IP, Array.Empty<byte>(), Bit.RandomBytes(20))
            );
            
            Reply(to: sender, message: reKeyMessage);
            _peerMsgId--; // this is not going to count as a sequenced message
            return;
/*
 parsed IKE_SA_INIT response 0 [ N(INVAL_KE) ]
peer didn't accept DH group CURVE_25519, it requested MODP_2048
initiating IKE_SA mpesa[9] to 197.250.65.132
generating IKE_SA_INIT request 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) N(FRAG_SUP) N(HASH_ALG) N(REDIR_SUP) ]
sending packet: from 159.69.13.126[500] to 197.250.65.132[500] (1128 bytes)
received packet: from 197.250.65.132[500] to 159.69.13.126[500] (619 bytes)
parsed IKE_SA_INIT response 0 [ SA KE No V V N(NATD_S_IP) N(NATD_D_IP) CERTREQ N(FRAG_SUP) V ]
received Cisco Delete Reason vendor ID
received Cisco Copyright (c) 2009 vendor ID
received FRAGMENTATION vendor ID
selected proposal: IKE:AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048
received 2 cert requests for an unknown ca
sending cert request for "CN=VPN root CA"
authentication of '159.69.13.126' (myself) with pre-shared key
establishing CHILD_SA mpesa{5}
generating IKE_AUTH request 1 [ IDi N(INIT_CONTACT) CERTREQ IDr AUTH SA TSi TSr N(MOBIKE_SUP) N(ADD_4_ADDR) N(ADD_4_ADDR) N(ADD_4_ADDR) N(ADD_4_ADDR) N(ADD_4_ADDR) N(ADD_6_ADDR) N(EAP_ONLY) N(MSG_ID_SYN_SUP) ]
sending packet: from 159.69.13.126[4500] to 197.250.65.132[4500] (480 bytes)
received packet: from 197.250.65.132[4500] to 159.69.13.126[4500] (256 bytes)
parsed IKE_AUTH response 1 [ V IDr AUTH SA TSi TSr N(ESP_TFC_PAD_N) N(NON_FIRST_FRAG) N(MOBIKE_SUP) ]
authentication of '197.250.65.132' with pre-shared key successful
*/
        }

        // build key
        
        
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
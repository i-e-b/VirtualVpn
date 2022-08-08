using System.Net;
using RawSocketTest.Crypto;
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

        request.ReadPayloads(_peerCrypto); // pvpn/server.py:266

        switch (request.Exchange)
        {
            case ExchangeType.IKE_SA_INIT: // pvpn/server.py:268
                AssertState(SessionState.INITIAL, request);
                HandleSaInit(request, sender, sendZeroHeader);
                break;

            case ExchangeType.IKE_AUTH: // pvpn/server.py:287
                AssertState(SessionState.SA_SENT, request);
                Console.WriteLine("IKE_AUTH received");
                Console.WriteLine($"This session has Crypto.\r\n  Me-> {_myCrypto}\r\nThem-> {_peerCrypto}");
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

    private void HandleSaInit(IkeMessage request, IPEndPoint sender, bool sendZeroHeader)
    {
        Console.WriteLine("        Session: IKE_SA_INIT received");

        _peerNonce = request.GetPayload<PayloadNonce>()?.Data;

        // pick a proposal we can work with, if any
        var saPayload = request.GetPayload<PayloadSa>();
        if (saPayload is null) throw new Exception("IKE_SA_INIT did not contain any SA proposals");

        var chosenProposal = saPayload.GetProposalFor(EncryptionTypeId.ENCR_AES_CBC); // we only support AES CBC mode at the moment
        var payloadKe = request.GetPayload<PayloadKeyExchange>();
        var preferredDiffieHellman = chosenProposal?.GetTransform(TransformType.DH)?.Id;

        // make sure we ended up with one we agree on
        if (chosenProposal is null || payloadKe is null || preferredDiffieHellman is null
            || (uint)payloadKe.DiffieHellmanGroup != preferredDiffieHellman.Value
            || payloadKe.KeyData.Length < 1
            || payloadKe.KeyData[0] == 0)
        {
            // pvpn/server.py:274

            Console.WriteLine($"        Session: Could not find an agreeable proposition. Sending rejection to {sender.Address}:{sender.Port}");
            Reply(to: sender, message: BuildResponse(ExchangeType.IKE_SA_INIT, sendZeroHeader, null,
                new PayloadNotify(IkeProtocolType.NONE, NotifyId.INVALID_KE_PAYLOAD, null, null)
            ));
            return;
        }

        // build key
        CryptoKeyExchange.DiffieHellman(payloadKe.DiffieHellmanGroup, payloadKe.KeyData, out var publicKey, out var sharedSecret);
        CreateKeyAndCrypto(chosenProposal, sharedSecret, null);

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
        // IEB: very suspect code
        /*
        keymat_fmt = struct.Struct('>{0}s{1}s{1}s{2}s{2}s{0}s{0}s'.format(prf.key_size, integ.key_size, cipher.key_size))
        keymat = prf.prfplus(skeyseed, self.peer_nonce+self.my_nonce+self.peer_spi+self.my_spi)
        self.sk_d, sk_ai, sk_ar, sk_ei, sk_er, sk_pi, sk_pr = keymat_fmt.unpack(bytes(next(keymat) for _ in range(keymat_fmt.size)))*/
        
        var totalSize = 3*prf.KeySize + 2*integ.KeySize + 2*cipher.KeySize;
        var seed = _peerNonce.Concat(_localNonce).Concat(Bit.UInt64ToBytes(_peerSpi)).Concat(Bit.UInt64ToBytes(_localSpi)).ToArray();
        var keySource = prf.HashFont(sKeySeed, seed, includeCount: true).Take(totalSize).ToArray();
        
        var idx = 0;
        _skD = Bit.Subset(prf.KeySize, keySource, ref idx);
        var skAi = Bit.Subset(integ.KeySize, keySource, ref idx);
        var skAr = Bit.Subset(integ.KeySize, keySource, ref idx);
        var skEi = Bit.Subset(cipher.KeySize, keySource, ref idx);
        var skEr = Bit.Subset(cipher.KeySize, keySource, ref idx);
        var skPi = Bit.Subset(prf.KeySize, keySource, ref idx);
        var skPr = Bit.Subset(prf.KeySize, keySource, ref idx);
        
        // build crypto for both sides
        _myCrypto = new IkeCrypto(cipher, integ, prf, skEr, skAr, skPr, null);
        _peerCrypto = new IkeCrypto(cipher, integ, prf, skEi, skAi, skPi, null);
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
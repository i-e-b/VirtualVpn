using System.Net;
using RawSocketTest.Crypto;
using RawSocketTest.Payloads;

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
        var resp = new IkeMessage();
        resp.Exchange = exchange;
        resp.SpiI = _peerSpi;
        resp.SpiR = _localSpi;
        resp.MessageFlag = MessageFlag.Response;
        resp.MessageId = (uint)_peerMsgId;
        resp.Payloads.AddRange(payloads);
        
        _peerMsgId++;
        
        return resp.ToBytes(sendZeroHeader, crypto); // should wrap payloads in PayloadSK if we have crypto
    }

    /// <summary>
    /// Handle an incoming key exchange message
    /// </summary>
    public void HandleIke(IkeMessage request, byte[] data, IPEndPoint sender, bool sendZeroHeader)
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
                AssertState(SessionState.INITIAL);
                
                _peerNonce = request.GetPayload<PayloadNonce>()?.RandomData;
                
                // pick a proposal we can work with, if any
                var chosenProp = request.GetPayload<PayloadSa>()?.GetProposalFor(EncryptionTypeId.ENCR_AES_CBC); // we only support AES CBC mode at the moment
                var payloadKe = request.GetPayload<PayloadKeyExchange>();
                var preferredDiffieHellman = chosenProp?.GetTransform(TransformType.DH)?.Id;

                // make sure we ended up with one we agree on
                if (chosenProp is null || payloadKe is null || preferredDiffieHellman is null
                    || (uint)payloadKe.DiffieHellmanGroup != preferredDiffieHellman.Value
                    || payloadKe.KeyData.Length < 1
                    || payloadKe.KeyData[0] == 0)
                { // pvpn/server.py:274
                    
                    Reply(to: sender, message: BuildResponse(ExchangeType.IKE_SA_INIT, sendZeroHeader, null, 
                        new PayloadNotify(IkeProtocolType.NONE, NotifyId.INVALID_KE_PAYLOAD, null, null)
                        ));
                    return;
                }
                
                // build key
                IkeCrypto.DiffieHellman(payloadKe.DiffieHellmanGroup, payloadKe.KeyData, out var publicKey, out var sharedSecret);
                // IEB: left off here

                break;

            case ExchangeType.IKE_AUTH: // pvpn/server.py:287
                break;

            case ExchangeType.INFORMATIONAL: // pvpn/server.py:315
                break;

            case ExchangeType.CREATE_CHILD_SA: // pvpn/server.py:340
                break;

            
            default:
               throw new Exception($"Unexpected request: {request.Exchange.ToString()}");
        }

        //########## TEST JUNK ############
        /*Console.WriteLine($"I should handle a {data.Length} byte session packet from {sender.Address}");
        
        request.SpiR = Bit.RandomSpi(); // assign ourself an SPI (will need to send to other side)
        Console.WriteLine($"    I started a new session with spi-r={request.SpiR:x16} and spi-i={request.SpiI:x16}");
            
        // TEMP STUFF (should be in session)...
            
        // reply with a responder SPI and changed flags
        request.MessageFlag = MessageFlag.Response;

        _server.SendRaw(request.ToBytes(sendZeroHeader), sender, out var sent);
        Console.WriteLine($"    Replied with {sent} bytes (echo with flipped flags)");
        // after this, we get a call on 4500 port to continue encrypted
        */
    }

    private void Reply(IPEndPoint to, byte[] message)
    {
        _lastMessageBytes = message;
        _server.SendRaw(message, to, out _);
    }

    /// <summary>
    /// Throw an exception if we're not in the expected state.
    /// Otherwise do nothing
    /// </summary>
    private void AssertState(SessionState expected)
    {
        if (_state != expected) throw new Exception($"Expected to be in state {expected.ToString()}, but was in {_state.ToString()}");
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
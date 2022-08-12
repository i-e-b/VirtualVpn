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
/// Negotiates and handles a single VPN session between self and one peer.
/// Most of this is covered by RFC 5996: https://datatracker.ietf.org/doc/html/rfc5996
/// </summary>
internal class VpnSession
{
    private const string PreSharedKeyString = "ThisIsForTestOnlyDontUse";
    //## State machine vars ##//
    
    private SessionState _state;
    
    /// <summary>sequence number for receiving</summary>
    private long _maxSeq = -1;
    /// <summary>sequence number for sending</summary>
    private readonly long _seqOut;
    
    private long _peerMsgId;
    private byte[]? _lastSentMessageBytes;
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
            Console.WriteLine($"    Incoming IKE message {request.Exchange.ToString()} {request.MessageId}");
            HandleIkeInternal(request, sender, sendZeroHeader);
            
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
            if (_lastSentMessageBytes is null)
            {
                Console.WriteLine("    Asked to repeat a message we didn't send? This session has faulted");
                // TODO: kill the session? respond with a failure message?
                return;
            }

            Console.WriteLine("    Asked to repeat a message we sent. Directly re-sending.");
            _server.SendRaw(_lastSentMessageBytes, sender, out _); // don't add zero pad again?
            return;
        }

        // make sure we're in sequence
        if (request.MessageId != _peerMsgId)
        {
            //Console.WriteLine($"Request is out of sequence. Expected {_peerMsgId}, but got {request.MessageId}. Will respond anyway.");
            Console.WriteLine($"Request is out of sequence. Expected {_peerMsgId}, but got {request.MessageId}. Not responding");
            return;
        }

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
                break;

            case ExchangeType.INFORMATIONAL: // pvpn/server.py:315
                AssertState(SessionState.ESTABLISHED, request);
                Console.WriteLine("INFORMATIONAL received");
                break;

            case ExchangeType.CREATE_CHILD_SA: // pvpn/server.py:340
                AssertState(SessionState.ESTABLISHED, request);
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
        var chosenChildProposal = sa.GetProposalFor(EncryptionTypeId.ENCR_AES_CBC);
        if (chosenChildProposal is null)
        {
            Console.WriteLine("    FATAL: could not find a compatible Child SA");
            // TODO: how do we reject?
            return;
        }
        
        var childKey = CreateChildKey(chosenChildProposal, _peerNonce, _localNonce);
        Console.WriteLine($"    New ESP SPI = {childKey.SpiIn:x8}");
        chosenChildProposal.SpiData = Bit.UInt32ToBytes(childKey.SpiIn); // Used to refer to the child SA in ESP messages?
        chosenChildProposal.SpiSize = 4;
        
        if (_lastSentMessageBytes is null) throw new Exception("IKE_AUTH stage reached without recording a last sent message? Auth cannot proceed.");
        
        // pvpn/server.py:301
        var responsePayloadIdr = new PayloadIDr(IdType.ID_IPV4_ADDR, new byte[]{185,81,252,44}, 0, 0); // should be configured
        var mySkp = _myCrypto?.SkP;
        if (mySkp is null) throw new Exception("Local SK-p not established before IKE_AUTH received");
        var authData = GeneratePskAuth(_lastSentMessageBytes, _peerNonce, responsePayloadIdr, mySkp); // I think this is based on the last thing we sent
        
        // pvpn/server.py:309
        // Send our Child-SA message back
        var response = BuildResponse(ExchangeType.CREATE_CHILD_SA, /*sendZeroHeader*/ false, _myCrypto, 
            new PayloadSa(chosenChildProposal),
            tsi, tsr, // just accept whatever traffic selectors. We're virtual.
            responsePayloadIdr,
            new PayloadAuth(AuthMethod.PSK, authData)
        );
        
        var cpPayload = request.GetPayload<PayloadCp>();
        if (cpPayload is null) Console.WriteLine("    No Configuration (CP) payload");
        else Console.WriteLine("    Configuration (CP) payload present");
        // deliberately ignoring 'CP' for now, but it probably is required
        
        // IEB: continue from here. I'm probably serialising something badly.
        // If I don't send the 0000 header, it goes quiet. Looks like it's 4 or 6 bytes off though?
        // is my header wrong? Spi lengths? 
        /*
Aug 11 15:48:24 Gertrud charon: 16[NET] sending packet: from 159.69.13.126[4500] to 185.81.252.44[4500] (480 bytes)
Aug 11 15:48:24 Gertrud charon: 06[ENC] no message rules specified for this message type
Aug 11 15:48:24 Gertrud charon: 06[NET] received unsupported IKE version 7.10 from 185.81.252.44, sending INVALID_MAJOR_VERSION  <--- this is about 4 bytes prev to where it should be.
         */
        
        // Experimental: patch in the new 4 byte SPI instead of the old 8 byte one
        /*var hackedResponse = response.Take(4+4).Concat(response.Skip(12)).ToArray();
        var spiBytes = Bit.UInt32ToBytes(childKey.SpiIn);
        hackedResponse[4] = spiBytes[0];
        hackedResponse[5] = spiBytes[1];
        hackedResponse[6] = spiBytes[2];
        hackedResponse[7] = spiBytes[3];
        Console.WriteLine(Bit.Describe("chopped 4 bytes from spi", hackedResponse));*/
        
        // Completely fake from MPesa session, but still fails.
        // IEB: Am I sending this from a bad connection (it thinks I'm on port 500 still?)
        response = new byte[]{ // zero, spi,spi, exchange, version...
     0x00,    0x00,    0x00,    0x00,/**/0x47,    0x24,    0xB6,    0x6A,    0x2C,    0x74,    0xC9,    0x13,/**/0xD3,    0x67,    0x90,    0x4C
,    0x1E,    0xA9,    0x3C,    0xB5,/**/0x2E,/**/0x20,/**/0x23,    0x20,    0x00,    0x00,    0x00,    0x01,    0x00,    0x00,    0x00,    0xFC
,    0x2B,    0x00,    0x00,    0xE0,    0xC9,    0x58,    0x36,    0x4A,    0xC7,    0x9C,    0x2C,    0xE7,    0x2F,    0x4E,    0x6A,    0x35
,    0xB3,    0x7D,    0xC3,    0x77,    0x03,    0xDD,    0x05,    0x8D,    0xB3,    0x65,    0x20,    0xE1,    0xA4,    0xB5,    0x11,    0x1A
,    0x3B,    0xEA,    0x70,    0x0D,    0xD0,    0xE2,    0x7E,    0xCC,    0x35,    0x44,    0xA0,    0x8A,    0xD6,    0x61,    0x64,    0x4A
,    0x4C,    0x8C,    0xAF,    0x5B,    0xB4,    0x61,    0xB4,    0x54,    0xDA,    0x2B,    0x75,    0x69,    0x3F,    0x3F,    0x28,    0xA2
,    0x1A,    0xC7,    0xC9,    0x31,    0xF6,    0x12,    0x93,    0xBD,    0x4F,    0x9A,    0xE7,    0x99,    0x09,    0x37,    0xA5,    0x68
,    0xE4,    0x51,    0x6D,    0x49,    0x96,    0xA2,    0x24,    0xF6,    0x1D,    0x1D,    0x66,    0xBC,    0x32,    0x20,    0x36,    0xD2
,    0xDE,    0x01,    0xBB,    0x06,    0x6B,    0xB9,    0x83,    0xD4,    0x06,    0x56,    0x2C,    0x14,    0xA9,    0x7D,    0x00,    0xA3
,    0xAB,    0xBC,    0x6C,    0xBF,    0x15,    0x5E,    0x82,    0xB7,    0x9C,    0x16,    0x02,    0xB9,    0x68,    0xE5,    0xDD,    0x9A
,    0x46,    0x39,    0x91,    0xAC,    0xF5,    0x5C,    0xFE,    0x0F,    0xEA,    0x9A,    0x0A,    0x1D,    0x53,    0xD0,    0x74,    0x90
,    0x37,    0x98,    0x56,    0x10,    0x4D,    0xCF,    0x70,    0x2F,    0x34,    0x72,    0x2D,    0xA9,    0x97,    0x06,    0x8D,    0x6E
,    0xB8,    0xD0,    0x0D,    0xE9,    0xE6,    0xDA,    0xE7,    0x63,    0x46,    0x46,    0xB1,    0xF5,    0x04,    0xBD,    0x23,    0x4A
,    0x97,    0xA2,    0x83,    0xC8,    0x73,    0xD1,    0xB6,    0x63,    0x60,    0xCA,    0x3A,    0x18,    0x65,    0x4A,    0x6A,    0xD7
,    0x0A,    0xE7,    0x10,    0x33,    0xCF,    0x96,    0x1B,    0x05,    0xB8,    0xF1,    0x10,    0xE7,    0x02,    0x8F,    0x22,    0x2A
,    0xC4,    0xD3,    0xA6,    0xA6,    0xEF,    0xEB,    0xB2,    0xA1,    0x61,    0x65,    0x0A,    0xCD,    0x4C,    0xE5,    0xBA,    0x40
        };
        
        // Send reply.
        Console.WriteLine($"    Sending IKE_AUTH response to peer {sender.Address} : {sender.Port}");
        Reply(to: sender, response);
        
        Console.WriteLine("    Setting state to established");
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
        
        //Console.WriteLine($"PSK message: {payload.Describe()}");

        var prefix = new byte[] { (byte)payload.IdType, 0, 0, 0 };
        var peerId = payload.IdData;
        var idxTick = prefix.Concat(peerId).ToArray();
        var octetPad = prf.Hash(skP, idxTick);
        
        var bulk = messageData.Concat(nonce).Concat(octetPad).ToArray();
        
        //Console.WriteLine($"#### {Bit.Describe("IDx'", idxTick)}");
        //Console.WriteLine($"#### {Bit.Describe("SK_p", skP)}");
        //Console.WriteLine($"#### {Bit.Describe("prf(Sk_px, IDx')", octetPad)}");
        //Console.WriteLine($"#### {Bit.Describe("octets =  message + nonce + prf(Sk_px, IDx') ", messageData)}"); // expect ~ 1192 bytes
        
        var psk = Encoding.ASCII.GetBytes(PreSharedKeyString);
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
        _lastSentMessageBytes = message;
        _server.SendRaw(message, to, out _);
        _peerMsgId++;
        
        var name = @$"C:\temp\IKEv2-Reply_{_peerMsgId}_Port-{to.Port}_IKE.bin";
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
        
        var rawMessage = _myCrypto.DecryptEsp(data, out var nextHeader);

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
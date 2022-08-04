using System.Net;

namespace RawSocketTest;

internal class VpnSession
{
    // state machine vars
    private long _maxSeq = -1;
    private SessionState _state;
    
    // locked for session
    private readonly UdpServer _server;
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
        return true; // temp
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

    /// <summary>
    /// Handle an incoming key exchange message (expecting IKE_AUTH)?
    /// </summary>
    public void HandleIke(IkeMessage ikeMessage, byte[] data, IPEndPoint sender, bool sendZeroHeader)
    {
        // pvpn/server.py:260
        LastTouchUtc = DateTime.UtcNow;
        
        Console.WriteLine($"I should handle a {data.Length} byte session packet from {sender.Address}");
        
        ikeMessage.SpiR = Bit.RandomSpi(); // assign ourself an SPI (will need to send to other side)
        Console.WriteLine($"    I started a new session with spi-r={ikeMessage.SpiR:x16} and spi-i={ikeMessage.SpiI:x16}");
            
        // TEMP STUFF (should be in session)...
            
        // reply with a responder SPI and changed flags
        ikeMessage.MessageFlag = MessageFlag.Response;

        _server.SendRaw(ikeMessage.ToBytes(sendZeroHeader), sender, out var sent);
        Console.WriteLine($"    Replied with {sent} bytes (echo with flipped flags)");
        // after this, we get a call on 4500 port to continue encrypted
    }

    /// <summary>
    /// Handle an incoming SPE message
    /// </summary>
    public void HandleSpe(byte[] data, IPEndPoint sender)
    {
        Console.WriteLine("SPE message (not yet handled)");
    }
}
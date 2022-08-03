using System.Net;

namespace RawSocketTest;

internal class VpnSession
{
    private readonly UdpServer _server;
    private readonly IkeMessage _initialMessage;
    private long _maxSeq = -1;

    public VpnSession(UdpServer server, IkeMessage initialMessage)
    {
        _server = server;
        _initialMessage = initialMessage;
    }
    

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

    public void Handle(byte[] data, IPEndPoint sender)
    {
        Console.WriteLine($"I should handle a {data.Length} byte session packet from {sender.Address}");
    }
}
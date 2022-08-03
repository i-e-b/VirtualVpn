using System.Net;
using SkinnyJson;

namespace RawSocketTest;

public class VpnServer : IDisposable
{
    private const int IKE_HEADER = 0;
    
    private int _messageCount;
    private readonly UdpServer _server;
    private readonly Dictionary<ulong, VpnSession> _sessions = new();

    public VpnServer()
    {
        _server = new UdpServer(IkeResponder, SpeResponder);
    }

    public void Run()
    {
        _messageCount = 0;
        Console.WriteLine("Setup");
        Json.DefaultParameters.EnableAnonymousTypes = true;

// Use Gerty for testing. Run "JustListen" to check your connection is working.
// You may need to do lots of firewall poking and NAT rules.
// Switch on ipsec on Gerty (`ipsec restart`), make sure there is a ruleset for the test PC.

//var target = new IPEndPoint(new IPAddress(new byte[]{197,250,65,132}), 500); // M-P
        var target = new IPEndPoint(new IPAddress(new byte[] { 159, 69, 13, 126 }), 500); // Gerty

        Thread.Sleep(1000);

        _server.Start();

        Console.WriteLine("trying to send raw");

        var message = new IkeMessage
        {
            SpiI = Bit.RandomSpi(),
            SpiR = 0,
            Version = IkeVersion.IkeV2,
            Exchange = ExchangeType.IKE_SA_INIT,
            MessageFlag = MessageFlag.Initiator,
            MessageId = 0,
            FirstPayload = PayloadType.NONE
        };

// INIT comes with these payloads: SA(33), KE(34), Nonce(40), Vendor ID (43), Notify(41)
//message.AddPayload(PayloadType.SA, new byte[1]);

        var buf = message.ToBytes();

        var limit = 50;
        for (int i = 0; i < limit; i++)
        {
            // contact other side first:
            //server.SendIke(buf, target, out var sent);
            //Console.WriteLine($"Sent {sent} bytes. Waiting for response ({i+1} of {limit})");
            //Thread.Sleep(500);

            // wait for other side to contact:
            Console.Write(".");
            Thread.Sleep(1500);
        }
    }



    /// <summary>
    /// Responds to port 500 traffic
    /// </summary>
    private void IkeResponder(byte[] rawData, IPEndPoint sender)
    {
        // write capture to file for easy testing
        _messageCount++;
        var name = @$"C:\temp\IKEv2-{_messageCount}_Port-{sender.Port}_IKE.bin";
        File.WriteAllBytes(name, rawData);
        Console.WriteLine($"Got a 500 packet -- {name}");
        
        IkeSessionResponder(rawData, sender, sendZeroHeader: false);
    }

    private void IkeSessionResponder(byte[] data, IPEndPoint sender, bool sendZeroHeader)
    {
        var ikeMessage = IkeMessage.FromBytes(data, 0);

        // Write interpretation to console
        //var str = Json.Freeze(ikeMessage);
        //Console.WriteLine(str);
        Console.WriteLine("Got a 500 packet...");

        if (ikeMessage.Exchange == ExchangeType.IKE_SA_INIT) // start of an IkeV2 session
        {
            Console.WriteLine("    it's for a new session");
            if (_sessions.ContainsKey(ikeMessage.SpiI)) // we have a dangling session
            {
                Console.WriteLine("        it duplicates an old session");
                // Here we kill the old session and start another.
                // This is a vulnerability -- an attacker could DoS by wiping a session using session init spam
                // We could check for age here, and refuse the new session if the old one is not old enough.
                var oldSession = _sessions[ikeMessage.SpiI];
                _sessions.Remove(ikeMessage.SpiI);
                oldSession.Close();
            }

            // Start a new session
            ikeMessage.SpiR = Bit.RandomSpi(); // assign ourself an SPI (will need to send to other side)
            var newSession = new VpnSession(_server, ikeMessage);
            _sessions.Add(ikeMessage.SpiI, newSession);
            Console.WriteLine($"    I started a new session with spi-r={ikeMessage.SpiR:x16} and spi-i={ikeMessage.SpiI:x16}");
            
            // TEMP STUFF (should be in session)...
            
            // reply with a responder SPI and changed flags
            ikeMessage.MessageFlag = MessageFlag.Response;

            _server.SendIke(ikeMessage.ToBytes(sendZeroHeader), sender, out var sent);
            Console.WriteLine($"    Replied with {sent} bytes (echo with flipped flags)");
            // after this, we get a call on 4500 port...
        }

    }

    /// <summary>
    /// Responds to port 4500 traffic
    /// </summary>
    private void SpeResponder(byte[] data, IPEndPoint sender)
    {
        // write capture to file for easy testing
        _messageCount++;
        var name = @$"C:\temp\IKEv2-{_messageCount}_Port-{sender.Port}_SPE.bin";
        File.WriteAllBytes(name, data);
        Console.WriteLine($"Got a 4500 packet -- {name}");
        
        if (data.Length < 4 && data[0] == 0xff) // keep alive?
        {
            Console.WriteLine("    Looks like a keep-alive ping. Sending pong");
            _server.SendIke(data, sender, out _);
            return;
        }

        var idx = 0;
        var header = Bit.ReadInt32(data, ref idx); // not quite sure what this is about
        var spi = Bit.ReadUInt64(data, ref idx);

        if (header == IKE_HEADER) // start session?
        {
            Console.WriteLine("    SPI zero on 4500 -- sending to 500 (IKE) responder");
            var offsetData = data.Skip(4).ToArray();
            IkeSessionResponder(offsetData, sender, sendZeroHeader: true);
            return;
        }

        // reject unknown sessions
        if (!_sessions.ContainsKey(spi))
        {
            Console.WriteLine($"    Unknown session: 0x{spi:x16} -- not replying");
            return;
        }

        // if we get here, we have a new message (with encryption) for an existing session
        var session = _sessions[spi];
        idx = 4;
        var seq = Bit.ReadUInt32(data, ref idx);
        Console.WriteLine($"    Packet has sequence #{seq}");
        if (session.OutOfSequence(seq))
        {
            Console.WriteLine($"    Received out of sequence packet: {seq} -- not replying");
            return;
        }
        
        // verify the checksum
        var ok = session.VerifyMessage(data);
        if (!ok)
        {
            Console.WriteLine($"    Received packet with bad checksum: {seq} -- not replying");
            return;
        }
        
        // looks ok. Step the sequence number forward
        session.IncrementSequence(seq);

        // do decrypt, route, etc.
        session.Handle(data, sender);
        
        Console.WriteLine("    Looks like a fully valid message. Other side will expect a reply.");
    }



    public void Dispose()
    {
        _server.Dispose();
        GC.SuppressFinalize(this);
    }
}
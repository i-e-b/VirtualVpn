using System.Net;
using System.Text;
using RawSocketTest.Crypto;
using RawSocketTest.Enums;
using RawSocketTest.EspProtocol;
using RawSocketTest.Helpers;
using RawSocketTest.InternetProtocol;

// ReSharper disable BuiltInTypeReferenceStyle

namespace RawSocketTest;

public class ChildSa
{
    private readonly byte[] _spiIn;
    private readonly byte[] _spiOut;
    private readonly IkeCrypto _cryptoIn;
    private readonly IkeCrypto _cryptoOut;
    private readonly UdpServer? _server;
    private long _msgIdIn;
    private long _msgIdOut;
    private readonly HashSet<long> _msgWin;

    // pvpn/server.py:18
    public ChildSa(byte[] spiIn, byte[] spiOut, IkeCrypto cryptoIn, IkeCrypto cryptoOut, UdpServer? server)
    {
        _spiIn = spiIn;
        _spiOut = spiOut;
        _cryptoIn = cryptoIn;
        _cryptoOut = cryptoOut;
        _server = server;

        _msgIdIn = 1;
        _msgIdOut = 1;
        _msgWin = new HashSet<long>();
        
        var idx = 0;
        SpiIn = Bit.ReadUInt32(spiIn, ref idx);
        idx = 0;
        SpiOut = Bit.ReadUInt32(spiOut, ref idx);
    }

    public void IncrementMessageId(uint espPacketSequence)
    {
        _msgIdIn = (int)(espPacketSequence+1);
        

        while (_msgWin.Contains(_msgIdIn))
        {
            _msgWin.Remove(_msgIdIn);
            _msgIdIn++;
        }
    }

    public UInt32 SpiIn { get; set; }
    public UInt32 SpiOut { get; set; }

    public void HandleSpe(byte[] data, IPEndPoint sender)
    {
        Log.Info($"HandleSpe: data={data.Length} bytes, sender={sender}");
        
        var incomingIpv4Message = ReadSpe(data, out var espPkt);


        switch (incomingIpv4Message.Protocol)
        {
            // IEB: just for now, only respond to PING
            case IpV4Protocol.ICMP:
            {
                Log.Info("ICMP payload found");
            
                var ok = ByteSerialiser.FromBytes<IcmpPacket>(incomingIpv4Message.Payload, out var icmp);
                if (!ok) throw new Exception("Could not read ICMP packet");

                if (icmp.MessageType == IcmpType.EchoRequest) // this is a ping!
                {
                    ReplyToPing(sender, icmp, incomingIpv4Message);
                }

                break;
            }
            case IpV4Protocol.TCP:
            {
                Log.Info("Regular TCP/IP packet");
                Log.Debug("Payload as string: " + Encoding.ASCII.GetString(incomingIpv4Message.Payload));
                break;
            }
            case IpV4Protocol.UDP:
            {
                Log.Info("UDP packet tunnelled in. Not responding.");
                break;
            }
        }
        
        

        IncrementMessageId(espPkt.Sequence);
        
        // dump the crypto details if requested
        if (Settings.CaptureTraffic)
        {
            File.WriteAllText(Settings.FileBase + "CSA.txt",
                Bit.Describe("SPI-in", _spiIn) +
                Bit.Describe("SPI-out", _spiOut) +
                "\r\nCryptoIn=" + _cryptoIn.UnsafeDump() +
                "\r\nCryptoOut=" + _cryptoOut.UnsafeDump()
            );
        }
    }

    private void ReplyToPing(IPEndPoint sender, IcmpPacket icmp, IpV4Packet incomingIpv4Message)
    {
        Log.Info("    It's a ping. Constructing reply.");
        icmp.MessageType = IcmpType.EchoReply;
        icmp.MessageCode = 0;
        icmp.Checksum = 0;

        var checksum = IpV4Packet.CalculateChecksum(ByteSerialiser.ToBytes(icmp));
        icmp.Checksum = checksum;

        var icmpData = ByteSerialiser.ToBytes(icmp);
        var ipv4Reply = new IpV4Packet
        {
            Version = IpV4Version.Version4,
            Length = 5,
            ServiceType = 0,
            TotalLength = 20 + icmpData.Length, // calculate later?
            PacketId = 642, // should be random?
            Flags = IpV4HeaderFlags.DontFragment,
            FragmentIndex = 0,
            Ttl = 64,
            Protocol = IpV4Protocol.ICMP,
            Checksum = 0,
            Source = incomingIpv4Message.Destination,
            Destination = incomingIpv4Message.Source,
            Options = Array.Empty<byte>(),
            Payload = icmpData
        };

        checksum = IpV4Packet.CalculateChecksum(ByteSerialiser.ToBytes(ipv4Reply));
        ipv4Reply.Checksum = checksum;

        var encryptedData = WriteSpe(ipv4Reply);
        Reply(encryptedData, sender);
    }

    private void Reply(byte[] message, IPEndPoint to)
    {
        if (_server is null)
        {
            Log.Warn($"Can't send to {to.Address}, this Child SA has no UDP server connection");
            return;
        }
        
        _server.SendRaw(message, to, out _);

        _msgIdOut++;
    }

    /// <summary>
    /// Write SPE packet for an IPv4 payload.
    /// Encrypts and adds SPE checksum. IPv4 checksum must be written before calling
    /// </summary>
    public byte[] WriteSpe(IpV4Packet packet)
    {
        var plain = ByteSerialiser.ToBytes(packet);
        var encrypted = _cryptoOut.EncryptEsp(plain, IpProtocol.IPV4);
        
        var wrapper = new EspPacket{
            Sequence = (uint)_msgIdOut,
            Spi = SpiOut,
            Payload = encrypted
        };
        
        var message = ByteSerialiser.ToBytes(wrapper);
        _cryptoOut.AddChecksum(message);
        return message;
    }

    public IpV4Packet ReadSpe(byte[] encrypted, out EspPacket espPacket)
    {
        // sanity check
        if (encrypted.Length < 8) throw new Exception("EspPacket too short");
        
        var ok = ByteSerialiser.FromBytes<EspPacket>(encrypted, out espPacket);
        if (!ok) throw new Exception("Failed to deserialise EspPacket");

        // target check
        if (espPacket.Spi != SpiIn) throw new Exception($"Mismatch SPI. Expected {SpiIn:x8}, got {espPacket.Spi:x8}");
        if (espPacket.Sequence < _msgIdIn) throw new Exception($"Mismatch Sequence. Expected {_msgIdIn}, got {espPacket.Sequence}");
        
        // checksum
        var checkOk = _cryptoIn.VerifyChecksum(encrypted);
        if (!checkOk) throw new Exception("ESP Checksum failed");

        // decode
        var plain = _cryptoIn.DecryptEsp(espPacket.Payload, out var declaredProtocol);
        
        if (declaredProtocol != IpProtocol.IPV4) throw new Exception($"ESP delivered unsupported payload type: {declaredProtocol.ToString()}");
        
        ok = ByteSerialiser.FromBytes<IpV4Packet>(plain, out var ipv4);
        if (!ok) throw new Exception("Failed to deserialise IPv4 packet");
        
        return ipv4;
    }
}
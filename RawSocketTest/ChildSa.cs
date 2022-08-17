using System.Net;
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
        Log.Info($"Not yet implemented: HandleSpe; data={data.Length} bytes, sender={sender}");
        
        var ipPkt = ReadSpe(data, out var espPkt);
        
        
        
        
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
using NUnit.Framework;
using RawSocketTest;
using RawSocketTest.Crypto;
using RawSocketTest.Enums;
using RawSocketTest.Helpers;
using RawSocketTest.InternetProtocol;
using SkinnyJson;

namespace ProtocolTests;

[TestFixture]
public class ChildSaTests
{
    [Test]
    public void deserialising_ping()
    {
        Json.DefaultParameters.EnableAnonymousTypes = true;
        
        var data = new byte[]
        {
            0x45, 0x00, 0x00, 0x54, 0xB8, 0x08, 0x40, 0x00, 0x40, 0x01, 0x53, 0x62, 0xC0, 0xA8, 0x00, 0x28, 0x37, 0x37, 0x37, 0x37, 0x08, 0x00, 0x9D, 0x7D, 0x00, 0x0E, 0x00, 0x01, 0x1D, 0x95, 0xFC, 0x62, 0x00, 0x00, 0x00, 0x00, 0x7A, 0xA8, 0x07, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33,
            0x34, 0x35, 0x36, 0x37
        };
        
        var ok = ByteSerialiser.FromBytes<IpPacket>(data, out var basicPacket);
        
        Assert.True(ok, "Deserialising failed");
        
        Console.WriteLine(TypeDescriber.Describe(basicPacket));
        
        Assert.That(basicPacket.Version, Is.EqualTo(IpV4Version.Version4), "Version");
        Assert.That(basicPacket.Length, Is.EqualTo(5), "Length");
        Assert.That(basicPacket.ServiceType, Is.EqualTo(0), "ServiceType");
        Assert.That(basicPacket.TotalLength, Is.EqualTo(84), "TotalLength");
        Assert.That(basicPacket.PacketId, Is.EqualTo(47112), "PacketId");
        Assert.That(basicPacket.Flags, Is.EqualTo(IpV4HeaderFlags.DontFragment), "Flags");
        Assert.That(basicPacket.FragmentIndex, Is.EqualTo(0), "FragmentIndex");
        Assert.That(basicPacket.Ttl, Is.EqualTo(64), "Ttl");
        Assert.That(basicPacket.Checksum, Is.EqualTo(21346), "Checksum");
        Assert.That(basicPacket.Source.AsString, Is.EqualTo("192.168.0.40"), "IP source");
        Assert.That(basicPacket.Destination.AsString, Is.EqualTo("55.55.55.55"), "IP dest");
        Assert.That(basicPacket.Options, Is.Empty, "Options");
        
        Assert.That(basicPacket.Payload, Is.Not.Empty, "Payload");
        
    }

    [Test]
    public void can_decode_ping()
    {
        Log.SetLevel(LogLevel.Everything);
        Settings.CodeModeForDescription = true;
        
        // Key sources --
        //prfId=PRF_HMAC_SHA2_256, integId=AUTH_HMAC_SHA2_256_128, cipherId=ENCR_AES_CBC, keyLength=128
        var spiIn = new byte[] {0xCB, 0xA3, 0xD6, 0x56, };
        var spiOut = new byte[] {0xC9, 0x76, 0xDF, 0x62, };

        // CryptoIn=
        var skEr = new byte[] {0x02, 0x58, 0x30, 0xBE, 0x2D, 0xC1, 0xD2, 0xA5, 0x9F, 0xA8, 0x71, 0xA0, 0x5B, 0x51, 0x23, 0x4E, };
        var skAr = new byte[] {0x7E, 0x65, 0x46, 0xE1, 0xBB, 0x9A, 0x41, 0x54, 0x63, 0x49, 0x52, 0xAD, 0xDA, 0x7A, 0x5D, 0x75, 0x50, 0x94, 0x20, 0x42, 0xA2, 0x1D, 0x7E, 0xBC, 0x77, 0x07, 0xE4, 0x63, 0xE8, 0x7B, 0x0C, 0xC6, };
        // CryptoOut=
        var skEi = new byte[] {0x7D, 0xB0, 0xD2, 0xB8, 0x1E, 0xB4, 0x85, 0x82, 0x5F, 0x2A, 0x04, 0x4C, 0x98, 0x4A, 0x72, 0x1C, };
        var skAi = new byte[] {0xCB, 0x06, 0xD7, 0xAE, 0x56, 0xB9, 0x05, 0x95, 0x3C, 0xDE, 0x53, 0x55, 0x73, 0x1F, 0xDD, 0x07, 0x06, 0x28, 0x2D, 0x8B, 0xE7, 0xF5, 0x6C, 0xBC, 0x2C, 0x71, 0xDF, 0xF9, 0x9E, 0xBF, 0xE2, 0x1C, };

        // First 'ping' ESP:
        var esp0 = new byte[]
        {
            /*---- spi----------*/  /*-- seq -----------*/
            0xCB, 0xA3, 0xD6, 0x56, 0x00, 0x00, 0x00, 0x01,
            /* ---- IV ----------------------------------------------------------------------------------*/
            0x6E, 0x6F, 0x53, 0x06, 0xEA, 0x61, 0x0A, 0x13, 0x57, 0x3B, 0x94, 0xAF, 0x47, 0xA6, 0x09, 0x67,
            // cipher text ...
            0xCC, 0x0B, 0x63, 0xFB, 0x1C, 0xDE, 0x6C, 0xE2, 0x6B, 0xB0, 0x02, 0x17, 0x10, 0x9E, 0x15, 0x42, 0x74, 0x2E, 0x83, 0x4E, 0x6B, 0x89, 0xB4, 0xD6, 0xE0, 0x0B, 0xD3, 0x78, 0x03, 0x7F, 0x73, 0x47, 0x1F, 0x18, 0xB1, 0xF5, 0x51, 0x09, 0x44, 0x28,
            0xF6, 0xE8, 0xA7, 0x15, 0x32, 0x7A, 0x18, 0xB8, 0x9F, 0xCC, 0xAC, 0x24, 0x3F, 0x05, 0x3B, 0x81, 0x79, 0xA6, 0xA4, 0xCF, 0x78, 0x8C, 0xCE, 0xFE, 0xA1, 0xA7, 0x5A, 0xDA, 0xA3, 0x8E, 0x19, 0xA3, 0x8B, 0xA9, 0xCB, 0xBF, 0xD4, 0xE3, 0x38, 0xA6,
            0xD1, 0x9F, 0x1E, 0x85, 0xE2, 0x3F, 0x1A, 0x82, 0x35, 0x1F, 0x86, 0x50, 0xC1, 0x59, 0xEE, 0x72,
            
            /* --- checksum -----------------------------------------------------------------------------*/
            0xFB, 0xBE, 0x06, 0x76, 0xDB, 0x73, 0x74, 0xF2, 0xCB, 0x2F, 0x0A, 0xEA, 0x5D, 0xB5, 0xAF, 0xB5,
        };
        
        // Second 'ping' ESP: (should be the same except for anti-repeat bits)
        var esp1 = new byte[]
        {
            /*---- spi----------*/  /*-- seq -----------*/  /* ---- IV ----------------------------------------------------------------------------------*/ // cipher...
            0xCB, 0xA3, 0xD6, 0x56, 0x00, 0x00, 0x00, 0x02, 0xC2, 0x1E, 0x44, 0x99, 0x5B, 0xB8, 0x4D, 0x2A, 0xD4, 0xB5, 0x97, 0x91, 0x6D, 0x92, 0x7C, 0xEE, 0x9A, 0x3F, 0x69, 0x99, 0xF2, 0xB4, 0x16, 0x60, 0xAF, 0x26, 0x6A, 0xDB, 0xAE, 0x9C, 0x7B, 0xDF,
            0x6F, 0xCD, 0x6A, 0xD7, 0xCA, 0x1D, 0x35, 0x8B, 0xE9, 0x97, 0x6B, 0x22, 0xAD, 0xC0, 0x3C, 0x11, 0xF8, 0xB9, 0xDD, 0x4B, 0xCB, 0x58, 0x22, 0x43, 0xD6, 0x00, 0xF1, 0x55, 0x7C, 0x5D, 0x21, 0x52, 0xB1, 0x40, 0xB5, 0xED, 0xC1, 0x3B, 0x8F, 0x29,
            0x3A, 0xAA, 0x7C, 0x1F, 0xF7, 0x90, 0x68, 0x4D, 0xD6, 0xC6, 0x8E, 0xCE, 0xBD, 0x36, 0x00, 0x57, 0xA7, 0x66, 0x0D, 0xEA, 0x9C, 0x3D, 0xC5, 0x50, 0x54, 0x1B, 0x6C, 0xA6, 0xCB, 0xDC, 0xAC, 0x69, 0x0B, 0xDE, 0xB4, 0x16, 0xCF, 0x7E, 0xCC, 0x1B,
            /* --- checksum -----------------------------------------------------------------------------*/
            0x60, 0x91, 0x36, 0x7D, 0x16, 0x40, 0x72, 0x90, 0x68, 0x81, 0xB2, 0x05, 0xA4, 0x81, 0x6F, 0xED,
        };


        var cryptoIn = new IkeCrypto(
            new Cipher(EncryptionTypeId.ENCR_AES_CBC, 128),
            new Integrity(IntegId.AUTH_HMAC_SHA2_256_128),
            new Prf(PrfId.PRF_HMAC_SHA2_256),
            skEr, skAr, null, null
            );
        
        var cryptoOut = new IkeCrypto(
            new Cipher(EncryptionTypeId.ENCR_AES_CBC, 128),
            new Integrity(IntegId.AUTH_HMAC_SHA2_256_128),
            new Prf(PrfId.PRF_HMAC_SHA2_256),
            skEi, skAi, null, null
        );
        
        var subject = new ChildSa(spiOut, spiIn, // these are probably the wrong SPIs (should be 4 byte, not 8 byte). If this causes a problem, update the captures
            cryptoIn, cryptoOut);
        
        // quick test...
        var spi = esp0.Take(4).ToArray();
        var seq = esp0.Skip(4).Take(4).ToArray();
        Console.WriteLine($"SPI = 0x{Bit.HexString(spi)}");
        Console.WriteLine($"ESP Sequence = 0x{Bit.HexString(seq)}");
        
        // Decode!
        var payload = esp0.Skip(8).ToArray();
        var plain = cryptoIn.DecryptEsp(payload, out var next);
        
        Console.WriteLine(Bit.Describe("esp0_plain", plain));
        Console.WriteLine($"Declared payload: {next.ToString()} (from ESP)");
        
        Assert.That(plain.Length, Is.GreaterThanOrEqualTo(20), "Decrypted length is invalid"); // must be at least a complete IP header
        
        // https://en.wikipedia.org/wiki/IPv4#Header
        
        var idx = 0;
        var versionAndLength = plain[idx++];
        var version = (byte)(versionAndLength >> 4);
        var headerLength = (byte)(versionAndLength & 0x0f); // count of 32bit words in header
        Console.WriteLine($"Version = {Bit.BinString(version)} (should be 0000 0100)");
        Console.WriteLine($"Header length = {headerLength} (should be 5 unless 'options' used) -> {headerLength * 4} bytes");
        
        var serviceType = plain[idx++];
        Console.WriteLine($"Service type = 0x{serviceType:x2} (usually 0x00 in IPv4. In IPv6, it's split between DSCP and ECN)"); // https://en.wikipedia.org/wiki/Type_of_service
        
        var totalLength = Bit.ReadUInt16(plain, ref idx);
        Console.WriteLine($"Total length = {totalLength} (headers + data, must be >= 20)");
        
        var packetId = Bit.ReadUInt16(plain, ref idx);
        Console.WriteLine($"Packet id = 0x{packetId:x4}"); // just a unique number among fragments
        
        var flagsAndFrags = Bit.ReadUInt16(plain, ref idx);
        var flags = (byte)(flagsAndFrags >> 13);
        var fragmentIndex = flagsAndFrags & 0x1fff;
        Console.WriteLine($"Flags = {Bit.BinString(flags)} (expect 0000 0010 ?)"); // [ zero ] [ don't fragment ] [ more fragments ]
        Console.WriteLine($"Fragment offset = {fragmentIndex} (location in final packet data, in units of eight-byte blocks)");
        
        var ttl = plain[idx++];
        Console.WriteLine($"Time to live = {ttl}");
        var protocol = (IpV4Protocol)plain[idx++];
        Console.WriteLine($"Protocol = 0x{(byte)protocol:x2} ({protocol.ToString()})");
        
        var checksum = Bit.ReadUInt16(plain, ref idx);
        Console.WriteLine($"Checksum = 0x{checksum:x4}"); // https://en.wikipedia.org/wiki/Internet_checksum
        
        var source1 = plain[idx++]; var source2 = plain[idx++]; var source3 = plain[idx++]; var source4 = plain[idx++];
        Console.WriteLine($"Source = {source1}.{source2}.{source3}.{source4}");
        
        var dest1 = plain[idx++]; var dest2 = plain[idx++]; var dest3 = plain[idx++]; var dest4 = plain[idx++];
        Console.WriteLine($"Destination = {dest1}.{dest2}.{dest3}.{dest4}");

        if (idx < headerLength)
        {
            var optionLength = headerLength - idx;
            Console.WriteLine($"IP Options ({optionLength} bytes)");
            idx += optionLength;
        }
        else Console.WriteLine("No IP options");
        
        var dataLength = plain.Length - idx;
        Console.WriteLine($"Packet data has {dataLength} bytes");
        
        var subset = Bit.Subset(dataLength, plain, ref idx);
        Console.WriteLine(Bit.Describe("Packet payload", subset));

        if (protocol == IpV4Protocol.ICMP) // https://en.wikipedia.org/wiki/Ping_(networking_utility)#Message_format
        {
            idx = 0;
            var type = (IcmpType)subset[idx++];
            var code = subset[idx++]; // depends on type
            var icmpChecksum = Bit.Subset(2,subset, ref idx);
            var pingIdentifier = Bit.ReadUInt16(subset, ref idx);
            var pingSequence = Bit.ReadUInt16(subset, ref idx);
            var pingPayload = Bit.Subset(-1, subset, ref idx);
            
            Console.WriteLine($"ICMP message: Type={type.ToString()}; Code={code}; Checksum=0x{Bit.HexString(icmpChecksum)}");
            Console.WriteLine($"If ping, ID={pingIdentifier}; Sequence={pingSequence}; Payload={Bit.HexString(pingPayload)}");
        }

        // todo: set-up child SA test the whole message handling path
        Assert.Inconclusive();
    }
}
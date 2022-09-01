using System.Text;
using NUnit.Framework;
using SkinnyJson;
using VirtualVpn;
using VirtualVpn.Crypto;
using VirtualVpn.Enums;
using VirtualVpn.EspProtocol;
using VirtualVpn.EspProtocol.Payloads;
using VirtualVpn.EspProtocol.Payloads.PayloadSubunits;
using VirtualVpn.Helpers;

// ReSharper disable InconsistentNaming

namespace ProtocolTests;

[TestFixture]
public class CryptoTests
{
    [Test]
    public void esp_round_trip()
    {
        // for AES-CBC, key must be 16 to 32 bytes, in 8 byte increments
        var key = RndKey32Byte();

        var cipher = new Cipher(EncryptionTypeId.ENCR_AES_CBC, key.Length * 8);
        var subject = new IkeCrypto(cipher, null, null, key, null, null, null);

        // The cipher should pad data out to required size, and remove on decoding.
        // So, any size input data should work.
        var plain1 = Encoding.ASCII.GetBytes("This is a private message, you should not see it in the encrypted text.");

        var plain2 = Encoding.ASCII.GetBytes("This is a private message. Lorem Ipsum is simply dummy text of the printing and typesetting industry.");

        var msg1 = subject.Encrypt(plain1);
        var msg2 = subject.Encrypt(plain2);

        // Visual inspection that it was transformed
        Console.WriteLine(Convert.ToBase64String(plain1));
        Console.WriteLine(Convert.ToBase64String(msg1));
        Console.WriteLine();
        Console.WriteLine(Convert.ToBase64String(plain2));
        Console.WriteLine(Convert.ToBase64String(msg2));

        var recovered1 = subject.Decrypt(msg1);
        var recovered2 = subject.Decrypt(msg2);


        var expected1 = Encoding.ASCII.GetString(plain1);
        var actual1 = Encoding.ASCII.GetString(recovered1);
        Assert.That(actual1, Is.EqualTo(expected1), "First message not recovered");

        var expected2 = Encoding.ASCII.GetString(plain2);
        var actual2 = Encoding.ASCII.GetString(recovered2);
        Assert.That(actual2, Is.EqualTo(expected2), "Second message not recovered");
    }

    [Test]
    public void negotiation_round_trip()
    {
        // for AES-CBC, key must be 16 to 32 bytes, in 8 byte increments
        var key = RndKey32Byte();

        var cipher = new Cipher(EncryptionTypeId.ENCR_AES_CBC, key.Length * 8);
        var prf = new Prf(PrfId.PRF_HMAC_SHA2_256);
        var iv = RndIv(cipher.BlockSize);

        // NOTE: the IVs get updated, so there have to be separate sender and receiver cryptos for negotiation phase
        var subject1 = new IkeCrypto(cipher, null, prf, key, null, null, iv);
        var subject2 = new IkeCrypto(cipher, null, prf, key, null, null, iv);

        // The cipher should pad data out to required size, and remove on decoding.
        // So, any size input data should work.
        var plain1 = Encoding.ASCII.GetBytes("This is a private message, you should not see it in the encrypted text.");

        var plain2 = Encoding.ASCII.GetBytes("This is a private message. Lorem Ipsum is simply dummy text of the printing and typesetting industry.");

        var msg1 = subject1.Encrypt1(plain1, 0);
        var msg2 = subject1.Encrypt1(plain2, 1);

        // Visual inspection that it was transformed
        Console.WriteLine(Convert.ToBase64String(plain1));
        Console.WriteLine(Convert.ToBase64String(msg1));
        Console.WriteLine();
        Console.WriteLine(Convert.ToBase64String(plain2));
        Console.WriteLine(Convert.ToBase64String(msg2));

        var recovered1 = subject2.Decrypt1(msg1, 0, removePad: true);
        var recovered2 = subject2.Decrypt1(msg2, 1, removePad: true);

        var expected1 = Encoding.ASCII.GetString(plain1);
        var actual1 = Encoding.ASCII.GetString(recovered1);
        Assert.That(actual1, Is.EqualTo(expected1), "First message not recovered");

        var expected2 = Encoding.ASCII.GetString(plain2);
        var actual2 = Encoding.ASCII.GetString(recovered2);
        Assert.That(actual2, Is.EqualTo(expected2), "Second message not recovered");
    }

    [Test]
    public void checksums_dont_break_if_no_algorithm_given()
    {
        // for AES-CBC, key must be 16 to 32 bytes, in 8 byte increments
        var key = RndKey32Byte();
        var cipher = new Cipher(EncryptionTypeId.ENCR_AES_CBC, key.Length * 8);

        var subject = new IkeCrypto(cipher, null, null, key, null, null, null);

        var plain = Encoding.ASCII.GetBytes("This is a private message, you should not see it in the encrypted text.");

        var msg = subject.Encrypt(plain);
        subject.AddChecksum(msg, Array.Empty<byte>());

        var ok = subject.VerifyChecksum(msg);

        Assert.That(ok, Is.True, "checksum");

        var recovered = subject.Decrypt(msg);

        var expected = Encoding.ASCII.GetString(plain);
        var actual = Encoding.ASCII.GetString(recovered);
        Assert.That(actual, Is.EqualTo(expected), "First message not recovered");
    }

    [Test]
    public void checksums_pass_when_data_is_correct()
    {
        // for AES-CBC, key must be 16 to 32 bytes, in 8 byte increments
        var mainKey = RndKey32Byte();
        var checksumKey = RndKey32Byte();
        var cipher = new Cipher(EncryptionTypeId.ENCR_AES_CBC, mainKey.Length * 8);
        var integrity = new Integrity(IntegId.AUTH_HMAC_SHA2_256_128);

        var subject = new IkeCrypto(cipher, integrity, null, mainKey, checksumKey, null, null);

        var plain = Encoding.ASCII.GetBytes("This is a private message, you should not see it in the encrypted text.");

        var msg = subject.Encrypt(plain);
        subject.AddChecksum(msg, Array.Empty<byte>());

        var ok = subject.VerifyChecksum(msg);

        Assert.That(ok, Is.True, "checksum");

        var recovered = subject.Decrypt(msg);

        var expected = Encoding.ASCII.GetString(plain);
        var actual = Encoding.ASCII.GetString(recovered);
        Assert.That(actual, Is.EqualTo(expected), "First message not recovered");
    }

    [Test]
    public void checksums_fail_when_data_is_damaged()
    {
        // for AES-CBC, key must be 16 to 32 bytes, in 8 byte increments
        var mainKey = RndKey32Byte();
        var checksumKey = RndKey32Byte();
        var cipher = new Cipher(EncryptionTypeId.ENCR_AES_CBC, mainKey.Length * 8);
        var integrity = new Integrity(IntegId.AUTH_HMAC_SHA2_256_128);

        var subject = new IkeCrypto(cipher, integrity, null, mainKey, checksumKey, null, null);

        var plain = Encoding.ASCII.GetBytes("This is a private message, you should not see it in the encrypted text.");

        var msg = subject.Encrypt(plain);
        subject.AddChecksum(msg, Array.Empty<byte>());

        // do some damage
        msg[0] ^= 0x40;
        msg[^1] ^= 0x81;

        var ok = subject.VerifyChecksum(msg);

        Assert.That(ok, Is.False, "checksum");
    }

    [Test]
    public void ike_crypto_can_start()
    {
        // IkeCrypto has lots of static data
        _ = new IkeCrypto(new Cipher(EncryptionTypeId.ENCR_AES_CBC, 64), null, null, new byte[64], null, null, null);
    }

    [Test]
    public void byte_array_description()
    {
        var raw = new byte[]
        {
            0x29, 0x00, 0x00, 0x0C, 0x01, 0x00, 0x00, 0x00, 0x9F, 0x45, 0x0D, 0x7E, 0x26, 0x00, 0x00, 0x08,
            0x00, 0x00, 0x40, 0x00, 0x24, 0x00, 0x00, 0x19, 0x04, 0x87, 0xA6, 0x84, 0xF3, 0x97, 0x7E, 0x0B,
            0x24
        };

        Console.WriteLine(Bit.Describe("raw", raw));
    }

    /// <summary>
    /// Testing the core of SK deserialisation
    /// </summary>
    [Test]
    public void non_crypto_data()
    {
        // This came from strong-swan logs at 'enc 4' level
        var raw = new byte[]
        {
            0x29, 0x00, 0x00, 0x0C, 0x01, 0x00, 0x00, 0x00, 0x9F, 0x45, 0x0D, 0x7E, 0x26, 0x00, 0x00, 0x08,
            0x00, 0x00, 0x40, 0x00, 0x24, 0x00, 0x00, 0x19, 0x04, 0x87, 0xA6, 0x84, 0xF3, 0x97, 0x7E, 0x0B,
            0xEE, 0x7C, 0x12, 0xF7, 0x27, 0x63, 0x5B, 0xFC, 0x31, 0xB9, 0x8B, 0x13, 0xB0, 0x27, 0x00, 0x00,
            0x0C, 0x01, 0x00, 0x00, 0x00, 0xB9, 0x51, 0xFC, 0x2C, 0x21, 0x00, 0x00, 0x28, 0x02, 0x00, 0x00,
            0x00, 0xF5, 0xEA, 0xF1, 0x98, 0x34, 0x10, 0xD3, 0xC0, 0xE1, 0x5E, 0xA5, 0x7F, 0xB7, 0x64, 0x68,
            0x63, 0x85, 0xFE, 0xDB, 0xD6, 0x52, 0x1D, 0xF5, 0xB3, 0xBC, 0x0E, 0xE8, 0x4B, 0x55, 0x23, 0x99,
            0xA6, 0x2C, 0x00, 0x00, 0x94, 0x02, 0x00, 0x00, 0x60, 0x01, 0x03, 0x04, 0x09, 0xC7, 0x7C, 0x9A,
            0x2D, 0x03, 0x00, 0x00, 0x0C, 0x01, 0x00, 0x00, 0x0C, 0x80, 0x0E, 0x00, 0x80, 0x03, 0x00, 0x00,
            0x0C, 0x01, 0x00, 0x00, 0x0C, 0x80, 0x0E, 0x00, 0xC0, 0x03, 0x00, 0x00, 0x0C, 0x01, 0x00, 0x00,
            0x0C, 0x80, 0x0E, 0x01, 0x00, 0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x0C, 0x03, 0x00, 0x00,
            0x08, 0x03, 0x00, 0x00, 0x0D, 0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x0E, 0x03, 0x00, 0x00,
            0x08, 0x03, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
            0x08, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x02, 0x03, 0x04, 0x03, 0xC7, 0x7C, 0x9A,
            0x2D, 0x03, 0x00, 0x00, 0x0C, 0x01, 0x00, 0x00, 0x14, 0x80, 0x0E, 0x00, 0x80, 0x03, 0x00, 0x00,
            0x0C, 0x01, 0x00, 0x00, 0x14, 0x80, 0x0E, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x0C, 0x01, 0x00, 0x00,
            0x14, 0x80, 0x0E, 0x01, 0x00, 0x2D, 0x00, 0x00, 0x18, 0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00,
            0x10, 0x00, 0x00, 0xFF, 0xFF, 0x9F, 0x45, 0x0D, 0x7E, 0x9F, 0x45, 0x0D, 0x7E, 0x29, 0x00, 0x00,
            0x18, 0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x10, 0x00, 0x00, 0xFF, 0xFF, 0xB9, 0x51, 0xFC,
            0x2C, 0xB9, 0x51, 0xFC, 0x2C, 0x29, 0x00, 0x00, 0x08, 0x00, 0x00, 0x40, 0x0C, 0x29, 0x00, 0x00,
            0x0C, 0x00, 0x00, 0x40, 0x0D, 0xC0, 0xA8, 0x00, 0x03, 0x29, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x40,
            0x0D, 0x0A, 0x00, 0x00, 0x02, 0x29, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x40, 0x0D, 0x0A, 0x00, 0x00,
            0x03, 0x29, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x40, 0x0D, 0xC0, 0xA8, 0x00, 0x02, 0x29, 0x00, 0x00,
            0x0C, 0x00, 0x00, 0x40, 0x0D, 0x5E, 0x82, 0x6C, 0xF9, 0x29, 0x00, 0x00, 0x18, 0x00, 0x00, 0x40,
            0x0E, 0x2A, 0x01, 0x04, 0xF8, 0x0C, 0x0C, 0x95, 0xA7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x29, 0x00, 0x00, 0x08, 0x00, 0x00, 0x40, 0x21, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x40,
            0x24
        };

        int idx = 0;
        PayloadType npl = PayloadType.NONE;

        var msg = new PayloadIDi(raw, ref idx, ref npl);

        Console.WriteLine(Json.Freeze(msg));

        /*
This gets output from StrongSwan too -- so should check my keys against it.


Aug  8 14:21:58 Gertrud charon: 01[IKE] authentication of '159.69.13.126' (myself) with pre-shared key
Aug  8 14:21:58 Gertrud charon: 01[IKE] IDx' => 8 bytes @ 0x7f1f07a00850
Aug  8 14:21:58 Gertrud charon: 01[IKE]    0: 01 00 00 00 9F 45 0D 7E                          .....E.~
Aug  8 14:21:58 Gertrud charon: 01[IKE] SK_p => 32 bytes @ 0x7f1ec00055a0
Aug  8 14:21:58 Gertrud charon: 01[IKE]    0: BA BA 3F 2C F4 D3 58 58 C1 C3 E5 75 6D 6B 4F C8  ..?,..XX...umkO.
Aug  8 14:21:58 Gertrud charon: 01[IKE]   16: 4D 2E 00 7B E3 F2 AB 71 7B 85 7C A0 31 C7 F3 ED  M..{...q{.|.1...
Aug  8 14:21:58 Gertrud charon: 01[IKE] octets = message + nonce + prf(Sk_px, IDx') => 968 bytes @ 0x7f1ec0006950
Aug  8 14:21:58 Gertrud charon: 01[IKE]    0: D8 F5 7B 32 5D F2 5E FE 00 00 00 00 00 00 00 00  ..{2].^.........
Aug  8 14:21:58 Gertrud charon: 01[IKE]   16: 21 20 22 08 00 00 00 00 00 00 03 88 22 00 02 C8  ! "........."...
Aug  8 14:21:58 Gertrud charon: 01[IKE]   32: 02 00 01 44 01 01 00 23 03 00 00 0C 01 00 00 0C  ...D...#........
Aug  8 14:21:58 Gertrud charon: 01[IKE]   48: 80 0E 00 80 03 00 00 0C 01 00 00 0C 80 0E 00 C0  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]   64: 03 00 00 0C 01 00 00 0C 80 0E 01 00 03 00 00 0C  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]   80: 01 00 00 0D 80 0E 00 80 03 00 00 0C 01 00 00 0D  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]   96: 80 0E 00 C0 03 00 00 0C 01 00 00 0D 80 0E 01 00  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  112: 03 00 00 0C 01 00 00 17 80 0E 00 80 03 00 00 0C  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  128: 01 00 00 17 80 0E 00 C0 03 00 00 0C 01 00 00 17  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  144: 80 0E 01 00 03 00 00 08 01 00 00 03 03 00 00 08  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  160: 03 00 00 0C 03 00 00 08 03 00 00 0D 03 00 00 08  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  176: 03 00 00 0E 03 00 00 08 03 00 00 05 03 00 00 08  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  192: 03 00 00 08 03 00 00 08 03 00 00 02 03 00 00 08  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  208: 02 00 00 04 03 00 00 08 02 00 00 08 03 00 00 08  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  224: 02 00 00 05 03 00 00 08 02 00 00 06 03 00 00 08  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  240: 02 00 00 07 03 00 00 08 02 00 00 02 03 00 00 08  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  256: 04 00 00 1F 03 00 00 08 04 00 00 20 03 00 00 08  ........... ....
Aug  8 14:21:58 Gertrud charon: 01[IKE]  272: 04 00 00 13 03 00 00 08 04 00 00 14 03 00 00 08  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  288: 04 00 00 15 03 00 00 08 04 00 00 1C 03 00 00 08  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  304: 04 00 00 1D 03 00 00 08 04 00 00 1E 03 00 00 08  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  320: 04 00 00 0F 03 00 00 08 04 00 00 10 03 00 00 08  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  336: 04 00 00 11 03 00 00 08 04 00 00 12 00 00 00 08  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  352: 04 00 00 0E 00 00 01 80 02 01 00 26 03 00 00 0C  ...........&....
Aug  8 14:21:58 Gertrud charon: 01[IKE]  368: 01 00 00 10 80 0E 00 80 03 00 00 0C 01 00 00 10  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  384: 80 0E 00 C0 03 00 00 0C 01 00 00 10 80 0E 01 00  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  400: 03 00 00 0C 01 00 00 14 80 0E 00 80 03 00 00 0C  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  416: 01 00 00 14 80 0E 00 C0 03 00 00 0C 01 00 00 14  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  432: 80 0E 01 00 03 00 00 08 01 00 00 1C 03 00 00 0C  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  448: 01 00 00 0E 80 0E 00 80 03 00 00 0C 01 00 00 0E  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  464: 80 0E 00 C0 03 00 00 0C 01 00 00 0E 80 0E 01 00  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  480: 03 00 00 0C 01 00 00 0F 80 0E 00 80 03 00 00 0C  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  496: 01 00 00 0F 80 0E 00 C0 03 00 00 0C 01 00 00 0F  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  512: 80 0E 01 00 03 00 00 0C 01 00 00 12 80 0E 00 80  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  528: 03 00 00 0C 01 00 00 12 80 0E 00 C0 03 00 00 0C  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  544: 01 00 00 12 80 0E 01 00 03 00 00 0C 01 00 00 13  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  560: 80 0E 00 80 03 00 00 0C 01 00 00 13 80 0E 00 C0  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  576: 03 00 00 0C 01 00 00 13 80 0E 01 00 03 00 00 08  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  592: 02 00 00 04 03 00 00 08 02 00 00 08 03 00 00 08  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  608: 02 00 00 05 03 00 00 08 02 00 00 06 03 00 00 08  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  624: 02 00 00 07 03 00 00 08 02 00 00 02 03 00 00 08  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  640: 04 00 00 1F 03 00 00 08 04 00 00 20 03 00 00 08  ........... ....
Aug  8 14:21:58 Gertrud charon: 01[IKE]  656: 04 00 00 13 03 00 00 08 04 00 00 14 03 00 00 08  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  672: 04 00 00 15 03 00 00 08 04 00 00 1C 03 00 00 08  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  688: 04 00 00 1D 03 00 00 08 04 00 00 1E 03 00 00 08  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  704: 04 00 00 0F 03 00 00 08 04 00 00 10 03 00 00 08  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  720: 04 00 00 11 03 00 00 08 04 00 00 12 00 00 00 08  ................
Aug  8 14:21:58 Gertrud charon: 01[IKE]  736: 04 00 00 0E 28 00 00 28 00 1F 00 00 C7 77 DC 28  ....(..(.....w.(
Aug  8 14:21:58 Gertrud charon: 01[IKE]  752: 17 96 97 D8 BD AA A8 5D 7B 2F 38 FF 98 B5 A4 64  .......]{/8....d
Aug  8 14:21:58 Gertrud charon: 01[IKE]  768: 0A 2F 77 6D 6E 52 AF B6 AC 4E D9 7D 29 00 00 24  ./wmnR...N.})..$
Aug  8 14:21:58 Gertrud charon: 01[IKE]  784: 95 19 AF B4 C2 BA 4A 00 66 1D 6E DD 2B 0F B3 B8  ......J.f.n.+...
Aug  8 14:21:58 Gertrud charon: 01[IKE]  800: AE 30 58 34 4E 0F 79 16 83 71 85 A4 A3 D5 B1 F3  .0X4N.y..q......
Aug  8 14:21:58 Gertrud charon: 01[IKE]  816: 29 00 00 1C 00 00 40 04 FC EA AC DC AA 63 43 3B  ).....@......cC;
Aug  8 14:21:58 Gertrud charon: 01[IKE]  832: 85 FE 0B D0 27 F5 18 9E B0 AA 48 D1 29 00 00 1C  ....'.....H.)...
Aug  8 14:21:58 Gertrud charon: 01[IKE]  848: 00 00 40 05 34 D6 A9 A8 62 48 44 C3 90 85 B5 29  ..@.4...bHD....)
Aug  8 14:21:58 Gertrud charon: 01[IKE]  864: 7F EB 94 E7 3F F0 B4 6B 29 00 00 08 00 00 40 2E  ....?..k).....@.
Aug  8 14:21:58 Gertrud charon: 01[IKE]  880: 29 00 00 10 00 00 40 2F 00 02 00 03 00 04 00 05  ).....@/........
Aug  8 14:21:58 Gertrud charon: 01[IKE]  896: 00 00 00 08 00 00 40 16 0E 95 F3 72 09 55 19 4E  ......@....r.U.N
Aug  8 14:21:58 Gertrud charon: 01[IKE]  912: 0A 5E EE 84 F3 09 E3 EE 06 CD BB E4 78 55 50 68  .^..........xUPh
Aug  8 14:21:58 Gertrud charon: 01[IKE]  928: 8A 9B 04 E7 3F 70 12 E4 B3 84 6B 41 CE C3 A2 55  ....?p....kA...U
Aug  8 14:21:58 Gertrud charon: 01[IKE]  944: 00 40 43 F0 C3 69 5A 5C 42 64 82 C4 8B 7F A1 87  .@C..iZ\Bd......
Aug  8 14:21:58 Gertrud charon: 01[IKE]  960: 05 26 11 8F C1 5A 27 73                          .&...Z's
Aug  8 14:21:58 Gertrud charon: 01[IKE] secret => 24 bytes @ 0x5555d1cd6f00
Aug  8 14:21:58 Gertrud charon: 01[IKE]    0: 54 68 69 73 49 73 46 6F 72 54 65 73 74 4F 6E 6C  ThisIsForTestOnl
Aug  8 14:21:58 Gertrud charon: 01[IKE]   16: 79 44 6F 6E 74 55 73 65                          yDontUse
Aug  8 14:21:58 Gertrud charon: 01[IKE] prf(secret, keypad) => 32 bytes @ 0x7f1ec0004920
Aug  8 14:21:58 Gertrud charon: 01[IKE]    0: 83 7B 85 EF 05 9A 81 D2 7D A7 0A 63 5C 59 03 A9  .{......}..c\Y..
Aug  8 14:21:58 Gertrud charon: 01[IKE]   16: D9 FD 31 55 8A 2D F1 9C A1 94 11 E6 57 A4 DA 37  ..1U.-......W..7
Aug  8 14:21:58 Gertrud charon: 01[IKE] AUTH = prf(prf(secret, keypad), octets) => 32 bytes @ 0x7f1ec0004f40
Aug  8 14:21:58 Gertrud charon: 01[IKE]    0: F5 EA F1 98 34 10 D3 C0 E1 5E A5 7F B7 64 68 63  ....4....^...dhc
Aug  8 14:21:58 Gertrud charon: 01[IKE]   16: 85 FE DB D6 52 1D F5 B3 BC 0E E8 4B 55 23 99 A6  ....R......KU#..

         */
    }

    [Test]
    public void validating_checksum_on_encrypted_data()
    {
        Settings.CaptureTraffic = false;
        var encrypted = File.ReadAllBytes("SampleData/SK-raw.bin");
        var sharedSecret = new byte[]
        {
            0x95, 0x31, 0x7D, 0xFA, 0x92, 0x0F, 0x4C, 0xB8, 0x52, 0xD6, 0xCE, 0xB3, 0xA7, 0x97, 0x40, 0x59, 0xEA, 0x0F, 0xE5, 0xDE, 0x7D, 0xF6, 0x08, 0xBD, 0xEB, 0x5A, 0xD5, 0xF8, 0x0E, 0xD0, 0xA2, 0x4D, 0x86, 0x56, 0xF5, 0x36, 0x67, 0xC5, 0xFA, 0xCE,
            0x71, 0xD7, 0xB9, 0x04, 0x65, 0xB5, 0xB7, 0x6E, 0xAF, 0xDA, 0x81, 0xC3, 0xEC, 0xAB, 0x91, 0xBA, 0xEE, 0x55, 0x30, 0x3C, 0xB3, 0xF1, 0xE4, 0xCF, 0x2D, 0xBB, 0x26, 0x4F, 0x2C, 0x55, 0xA8, 0x92, 0xF9, 0x30, 0x06, 0x4B, 0xC3, 0xB3, 0xF7, 0x51,
            0x7F, 0x5D, 0x29, 0x69, 0x67, 0x36, 0x5C, 0x3C, 0x2E, 0x6F, 0xBD, 0xB6, 0xC5, 0xF7, 0x08, 0x8A, 0xB7, 0x8B, 0x7E, 0xFD, 0x78, 0x36, 0xAF, 0x4F, 0xE3, 0x9F, 0xDC, 0x8D, 0x2F, 0x22, 0x2F, 0xB4, 0x13, 0x07, 0xE0, 0x6D, 0xAF, 0x08, 0x67, 0x8E,
            0xF3, 0x33, 0x33, 0xED, 0xF8, 0x63, 0x67, 0x9A, 0x81, 0xFE, 0x5B, 0xDC, 0x6E, 0x68, 0xD5, 0xBC, 0x6D, 0x57, 0x23, 0x32, 0x40, 0xBF, 0xA5, 0x79, 0x89, 0xED, 0xE2, 0x70, 0xCF, 0x4D, 0x88, 0xE5, 0x91, 0xF2, 0xA1, 0x8F, 0xB8, 0x40, 0x8D, 0x78,
            0x17, 0x44, 0xAA, 0x23, 0x2C, 0xBD, 0xF7, 0x31, 0xDA, 0xDA, 0x12, 0x39, 0x1D, 0x13, 0x9E, 0xED, 0x0E, 0x35, 0xB4, 0x18, 0xA5, 0xD9, 0x50, 0x4A, 0x4D, 0xFE, 0x20, 0xF3, 0xAA, 0x99, 0x23, 0x51, 0xC5, 0x84, 0x3A, 0x33, 0x07, 0x0D, 0x64, 0x82,
            0xF6, 0xF0, 0xB2, 0xE0, 0x21, 0xE6, 0xD6, 0x07, 0x1B, 0x96, 0x25, 0xF4, 0xF2, 0x64, 0x16, 0xEC, 0xB4, 0x53, 0x37, 0x4B, 0x08, 0x94, 0x08, 0x0A, 0xE3, 0x39, 0x15, 0x54, 0x26, 0x2F, 0xDA, 0xFB, 0xED, 0x75, 0x13, 0xA5, 0xE8, 0x38, 0xAC, 0xE7,
            0x23, 0x1A, 0x55, 0xC9, 0xBB, 0x0F, 0x62, 0x3E, 0x83, 0xDA, 0xEB, 0xFC, 0xBC, 0xDA, 0xF6, 0x87
        };
        var theirNonce = new byte[] { 0x06, 0x5E, 0xAE, 0xED, 0x97, 0xC0, 0xFD, 0x32, 0xE0, 0x6E, 0xB7, 0x63, 0xE2, 0x04, 0xBE, 0xA8, 0x4F, 0x08, 0x28, 0xFC, 0x56, 0xA7, 0x61, 0xDD, 0xA8, 0x80, 0xB9, 0x83, 0x60, 0xD2, 0x1C, 0xC3 };
        var myNonce = new byte[] { 0xFF, 0x80, 0x0E, 0x9C, 0x85, 0x1D, 0xB2, 0x2E, 0x6C, 0x3C, 0x0D, 0x4C, 0x8C, 0x8E, 0xA8, 0x79, 0x80, 0xFC, 0xBD, 0x5A, 0xA8, 0x35, 0x19, 0x30, 0xE4, 0xC3, 0xAE, 0x9C, 0x4B, 0xE0, 0xBA, 0x91 };
        var theirSpi = new byte[] { 0xAE, 0xB8, 0x98, 0x45, 0x5D, 0xBF, 0xB7, 0xBE };
        var mySpi = new byte[] { 0x43, 0x51, 0x2C, 0xB0, 0x70, 0x5D, 0x9B, 0xA6 };
        var pad = Encoding.ASCII.GetBytes(Prf.IKEv2_KeyPad);
        var psk = Encoding.ASCII.GetBytes("ThisIsForTestOnlyDontUse");

        IkeCrypto.CreateKeysAndCryptoInstances(false,
            theirNonce, myNonce, sharedSecret, theirSpi, mySpi,
            PrfId.PRF_HMAC_SHA2_256, IntegId.AUTH_HMAC_SHA2_256_128, EncryptionTypeId.ENCR_AES_CBC, keyLength: 128,
            null, out _, out var myCrypto, out var theirCrypto
        );

        // NOTE: this is how the PSK is calculated:
        Console.WriteLine(Bit.Describe("SkA", theirCrypto.SkA));
        var y = theirCrypto.Prf!.Hash(psk, pad);
        Console.WriteLine(Bit.Describe("prf(secret, keypad) ALT", y));


        var whole_their = theirCrypto.VerifyChecksum(encrypted);
        var whole_mine = myCrypto.VerifyChecksum(encrypted);

        var skData = encrypted.Skip(28).ToArray();
        Console.WriteLine(Bit.Describe("Data less header", skData));
        var sk_their = theirCrypto.VerifyChecksum(skData);
        var sk_mine = myCrypto.VerifyChecksum(skData);

        Console.WriteLine($"wt={whole_their}, wm={whole_mine}, skt={sk_their}, skm={sk_mine}");
        Assert.True(whole_their | whole_mine | sk_their | sk_mine, "None of the checksums passed");
    }

    [Test]
    public void decoding_encrypted_sk_payload()
    {
        Settings.CaptureTraffic = false;
        var encrypted = File.ReadAllBytes("SampleData/SK-raw.bin");
        var sharedSecret = new byte[]
        {
            0x95, 0x31, 0x7D, 0xFA, 0x92, 0x0F, 0x4C, 0xB8, 0x52, 0xD6, 0xCE, 0xB3, 0xA7, 0x97, 0x40, 0x59, 0xEA, 0x0F, 0xE5, 0xDE, 0x7D, 0xF6, 0x08, 0xBD, 0xEB, 0x5A, 0xD5, 0xF8, 0x0E, 0xD0, 0xA2, 0x4D, 0x86, 0x56, 0xF5, 0x36, 0x67, 0xC5, 0xFA, 0xCE,
            0x71, 0xD7, 0xB9, 0x04, 0x65, 0xB5, 0xB7, 0x6E, 0xAF, 0xDA, 0x81, 0xC3, 0xEC, 0xAB, 0x91, 0xBA, 0xEE, 0x55, 0x30, 0x3C, 0xB3, 0xF1, 0xE4, 0xCF, 0x2D, 0xBB, 0x26, 0x4F, 0x2C, 0x55, 0xA8, 0x92, 0xF9, 0x30, 0x06, 0x4B, 0xC3, 0xB3, 0xF7, 0x51,
            0x7F, 0x5D, 0x29, 0x69, 0x67, 0x36, 0x5C, 0x3C, 0x2E, 0x6F, 0xBD, 0xB6, 0xC5, 0xF7, 0x08, 0x8A, 0xB7, 0x8B, 0x7E, 0xFD, 0x78, 0x36, 0xAF, 0x4F, 0xE3, 0x9F, 0xDC, 0x8D, 0x2F, 0x22, 0x2F, 0xB4, 0x13, 0x07, 0xE0, 0x6D, 0xAF, 0x08, 0x67, 0x8E,
            0xF3, 0x33, 0x33, 0xED, 0xF8, 0x63, 0x67, 0x9A, 0x81, 0xFE, 0x5B, 0xDC, 0x6E, 0x68, 0xD5, 0xBC, 0x6D, 0x57, 0x23, 0x32, 0x40, 0xBF, 0xA5, 0x79, 0x89, 0xED, 0xE2, 0x70, 0xCF, 0x4D, 0x88, 0xE5, 0x91, 0xF2, 0xA1, 0x8F, 0xB8, 0x40, 0x8D, 0x78,
            0x17, 0x44, 0xAA, 0x23, 0x2C, 0xBD, 0xF7, 0x31, 0xDA, 0xDA, 0x12, 0x39, 0x1D, 0x13, 0x9E, 0xED, 0x0E, 0x35, 0xB4, 0x18, 0xA5, 0xD9, 0x50, 0x4A, 0x4D, 0xFE, 0x20, 0xF3, 0xAA, 0x99, 0x23, 0x51, 0xC5, 0x84, 0x3A, 0x33, 0x07, 0x0D, 0x64, 0x82,
            0xF6, 0xF0, 0xB2, 0xE0, 0x21, 0xE6, 0xD6, 0x07, 0x1B, 0x96, 0x25, 0xF4, 0xF2, 0x64, 0x16, 0xEC, 0xB4, 0x53, 0x37, 0x4B, 0x08, 0x94, 0x08, 0x0A, 0xE3, 0x39, 0x15, 0x54, 0x26, 0x2F, 0xDA, 0xFB, 0xED, 0x75, 0x13, 0xA5, 0xE8, 0x38, 0xAC, 0xE7,
            0x23, 0x1A, 0x55, 0xC9, 0xBB, 0x0F, 0x62, 0x3E, 0x83, 0xDA, 0xEB, 0xFC, 0xBC, 0xDA, 0xF6, 0x87
        };
        var theirNonce = new byte[] { 0x06, 0x5E, 0xAE, 0xED, 0x97, 0xC0, 0xFD, 0x32, 0xE0, 0x6E, 0xB7, 0x63, 0xE2, 0x04, 0xBE, 0xA8, 0x4F, 0x08, 0x28, 0xFC, 0x56, 0xA7, 0x61, 0xDD, 0xA8, 0x80, 0xB9, 0x83, 0x60, 0xD2, 0x1C, 0xC3 };
        var myNonce = new byte[] { 0xFF, 0x80, 0x0E, 0x9C, 0x85, 0x1D, 0xB2, 0x2E, 0x6C, 0x3C, 0x0D, 0x4C, 0x8C, 0x8E, 0xA8, 0x79, 0x80, 0xFC, 0xBD, 0x5A, 0xA8, 0x35, 0x19, 0x30, 0xE4, 0xC3, 0xAE, 0x9C, 0x4B, 0xE0, 0xBA, 0x91 };
        var theirSpi = new byte[] { 0xAE, 0xB8, 0x98, 0x45, 0x5D, 0xBF, 0xB7, 0xBE };
        var mySpi = new byte[] { 0x43, 0x51, 0x2C, 0xB0, 0x70, 0x5D, 0x9B, 0xA6 };
        var pad = Encoding.ASCII.GetBytes(Prf.IKEv2_KeyPad);
        var psk = Encoding.ASCII.GetBytes("ThisIsForTestOnlyDontUse");

        IkeCrypto.CreateKeysAndCryptoInstances(false,
            theirNonce, myNonce, sharedSecret, theirSpi, mySpi,
            PrfId.PRF_HMAC_SHA2_256, IntegId.AUTH_HMAC_SHA2_256_128, EncryptionTypeId.ENCR_AES_CBC, keyLength: 128,
            null, out _, out _, out var theirCrypto
        );

        // NOTE: this is how the PSK is calculated:
        Console.WriteLine(Bit.Describe("SkA", theirCrypto.SkA));
        var y = theirCrypto.Prf!.Hash(psk, pad);
        Console.WriteLine(Bit.Describe("prf(secret, keypad) ALT", y));

        var whole_their = theirCrypto.VerifyChecksum(encrypted);
        Assert.True(whole_their, "Checksum failed");

        var idx = 28; // IKE message header size
        // chop off head and tail
        var body = Bit.Subset(encrypted.Length - 28 - theirCrypto.Integrity!.HashSize, encrypted, ref idx);
        var bytes = theirCrypto.Decrypt(encrypted);

        Console.WriteLine(Bit.Describe("decrypted:", bytes));

        idx = 0;
        var nextPayload = PayloadType.IDi;

        var result = IkeMessage.ReadSinglePayload(bytes, null, ref idx, ref nextPayload, body);

        Console.WriteLine(Json.Freeze(result));
    }

    [Test]
    public void sk_payload_round_trip()
    {
        Settings.CaptureTraffic = false;
        var sharedSecret = new byte[]
        {
            0x95, 0x31, 0x7D, 0xFA, 0x92, 0x0F, 0x4C, 0xB8, 0x52, 0xD6, 0xCE, 0xB3, 0xA7, 0x97, 0x40, 0x59, 0xEA, 0x0F, 0xE5, 0xDE, 0x7D, 0xF6, 0x08, 0xBD, 0xEB, 0x5A, 0xD5, 0xF8, 0x0E, 0xD0, 0xA2, 0x4D, 0x86, 0x56, 0xF5, 0x36, 0x67, 0xC5, 0xFA, 0xCE,
            0x71, 0xD7, 0xB9, 0x04, 0x65, 0xB5, 0xB7, 0x6E, 0xAF, 0xDA, 0x81, 0xC3, 0xEC, 0xAB, 0x91, 0xBA, 0xEE, 0x55, 0x30, 0x3C, 0xB3, 0xF1, 0xE4, 0xCF, 0x2D, 0xBB, 0x26, 0x4F, 0x2C, 0x55, 0xA8, 0x92, 0xF9, 0x30, 0x06, 0x4B, 0xC3, 0xB3, 0xF7, 0x51,
            0x7F, 0x5D, 0x29, 0x69, 0x67, 0x36, 0x5C, 0x3C, 0x2E, 0x6F, 0xBD, 0xB6, 0xC5, 0xF7, 0x08, 0x8A, 0xB7, 0x8B, 0x7E, 0xFD, 0x78, 0x36, 0xAF, 0x4F, 0xE3, 0x9F, 0xDC, 0x8D, 0x2F, 0x22, 0x2F, 0xB4, 0x13, 0x07, 0xE0, 0x6D, 0xAF, 0x08, 0x67, 0x8E,
            0xF3, 0x33, 0x33, 0xED, 0xF8, 0x63, 0x67, 0x9A, 0x81, 0xFE, 0x5B, 0xDC, 0x6E, 0x68, 0xD5, 0xBC, 0x6D, 0x57, 0x23, 0x32, 0x40, 0xBF, 0xA5, 0x79, 0x89, 0xED, 0xE2, 0x70, 0xCF, 0x4D, 0x88, 0xE5, 0x91, 0xF2, 0xA1, 0x8F, 0xB8, 0x40, 0x8D, 0x78,
            0x17, 0x44, 0xAA, 0x23, 0x2C, 0xBD, 0xF7, 0x31, 0xDA, 0xDA, 0x12, 0x39, 0x1D, 0x13, 0x9E, 0xED, 0x0E, 0x35, 0xB4, 0x18, 0xA5, 0xD9, 0x50, 0x4A, 0x4D, 0xFE, 0x20, 0xF3, 0xAA, 0x99, 0x23, 0x51, 0xC5, 0x84, 0x3A, 0x33, 0x07, 0x0D, 0x64, 0x82,
            0xF6, 0xF0, 0xB2, 0xE0, 0x21, 0xE6, 0xD6, 0x07, 0x1B, 0x96, 0x25, 0xF4, 0xF2, 0x64, 0x16, 0xEC, 0xB4, 0x53, 0x37, 0x4B, 0x08, 0x94, 0x08, 0x0A, 0xE3, 0x39, 0x15, 0x54, 0x26, 0x2F, 0xDA, 0xFB, 0xED, 0x75, 0x13, 0xA5, 0xE8, 0x38, 0xAC, 0xE7,
            0x23, 0x1A, 0x55, 0xC9, 0xBB, 0x0F, 0x62, 0x3E, 0x83, 0xDA, 0xEB, 0xFC, 0xBC, 0xDA, 0xF6, 0x87
        };
        var theirNonce = new byte[] { 0x06, 0x5E, 0xAE, 0xED, 0x97, 0xC0, 0xFD, 0x32, 0xE0, 0x6E, 0xB7, 0x63, 0xE2, 0x04, 0xBE, 0xA8, 0x4F, 0x08, 0x28, 0xFC, 0x56, 0xA7, 0x61, 0xDD, 0xA8, 0x80, 0xB9, 0x83, 0x60, 0xD2, 0x1C, 0xC3 };
        var myNonce = new byte[] { 0xFF, 0x80, 0x0E, 0x9C, 0x85, 0x1D, 0xB2, 0x2E, 0x6C, 0x3C, 0x0D, 0x4C, 0x8C, 0x8E, 0xA8, 0x79, 0x80, 0xFC, 0xBD, 0x5A, 0xA8, 0x35, 0x19, 0x30, 0xE4, 0xC3, 0xAE, 0x9C, 0x4B, 0xE0, 0xBA, 0x91 };
        var theirSpi = new byte[] { 0xAE, 0xB8, 0x98, 0x45, 0x5D, 0xBF, 0xB7, 0xBE };
        var mySpi = new byte[] { 0x43, 0x51, 0x2C, 0xB0, 0x70, 0x5D, 0x9B, 0xA6 };

        IkeCrypto.CreateKeysAndCryptoInstances(false,
            theirNonce, myNonce, sharedSecret, theirSpi, mySpi,
            PrfId.PRF_HMAC_SHA2_256, IntegId.AUTH_HMAC_SHA2_256_128, EncryptionTypeId.ENCR_AES_CBC, keyLength: 128,
            null, out _, out var myCrypto, out _
        );

        var defaultProposal = new Proposal();
        var newPublicKey = new byte[256];

        ulong peerSpi = 123456;
        ulong localSpi = 987645;
        long msgId = 1;
        var bytes = VpnSession.BuildSerialMessage(ExchangeType.IKE_AUTH, MessageFlag.Response, false, false, myCrypto, peerSpi, localSpi, msgId,
            new PayloadSa(defaultProposal),
            new PayloadNonce(new byte[32]),
            new PayloadKeyExchange(DhId.DH_14, newPublicKey), // Pre-start our preferred exchange
            new PayloadNotify(IkeProtocolType.NONE, NotifyId.NAT_DETECTION_DESTINATION_IP, Array.Empty<byte>(), Bit.RandomBytes(20)),
            new PayloadNotify(IkeProtocolType.NONE, NotifyId.NAT_DETECTION_SOURCE_IP, Array.Empty<byte>(), Bit.RandomBytes(20))
        );

        var checksumOk = myCrypto.VerifyChecksum(bytes);
        Assert.True(checksumOk, "Checksum failed");

        var idx = 0;
        PayloadType nextPayload = PayloadType.NONE;
        var result = IkeMessage.ReadSinglePayload(bytes, myCrypto, ref idx, ref nextPayload);

        Console.WriteLine(Json.Freeze(result));
    }

    private static byte[] RndKey32Byte()
    {
        var key = new byte[32];
        var rnd = new Random();
        rnd.NextBytes(key);
        return key;
    }

    private byte[] RndIv(int cipherBlockSize)
    {
        var key = new byte[cipherBlockSize];
        var rnd = new Random();
        rnd.NextBytes(key);
        return key;
    }
}
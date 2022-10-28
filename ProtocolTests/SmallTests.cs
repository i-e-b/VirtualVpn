using System.Globalization;
using System.Text;
using NUnit.Framework;
using VirtualVpn.InternetProtocol;
using VirtualVpn.Logging;
using VirtualVpn.Web;

namespace ProtocolTests;

[TestFixture]
public class SmallTests
{
    [Test]
    public void enum_ordering_works()
    {
        Assert.True(LogLevel.Trace < LogLevel.Crypto, "enum order");
    }

    [Test]
    public void ipv4_describe_works()
    {
        var result = IpV4Address.Describe(0x12345678);
        Assert.That(result, Is.EqualTo("18.52.86.120"));
    }

    [Test]
    public void byte_search()
    {
        var needle = new byte[] { 50, 60, 40 };

        Assert.True(HttpHostHeaderRewriter.Contains(needle, needle, out var i), "self");
        Assert.That(i, Is.EqualTo(0));

        Assert.True(HttpHostHeaderRewriter.Contains(
            new byte[] { 10, 50, 60, 40 },
            needle, out i), "offset 1, end");
        Assert.That(i, Is.EqualTo(1));

        Assert.True(HttpHostHeaderRewriter.Contains(
            new byte[] { 50, 60, 40, 10 },
            needle, out i), "offset 2, start");
        Assert.That(i, Is.EqualTo(0));

        Assert.False(HttpHostHeaderRewriter.Contains(
            new byte[] { 10, 20, 50, 30, 40, 20, 60, 40, 10 },
            needle, out i), "mix 1");
        Assert.That(i, Is.EqualTo(-1));
        
        Assert.True(HttpHostHeaderRewriter.Contains(
            new byte[] { 10, 20, 50, 30, 40, 20, 50, 60, 40, 10 },
            needle, out i), "mix 2");
        Assert.That(i, Is.EqualTo(6));
        
        Assert.True(HttpHostHeaderRewriter.Contains(
            new byte[] { 10, 20, 30, 30, 40, 20, 50, 60, 40, 10 },
            needle, out i), "mix 3");
        Assert.That(i, Is.EqualTo(6));
        
        Assert.False(HttpHostHeaderRewriter.Contains(
            new byte[] { 10, 20, 30, 30, 40, 20, 50, 61, 40, 10 },
            needle, out i), "mix 4");
        Assert.That(i, Is.EqualTo(-1));
        
        Assert.True(HttpHostHeaderRewriter.Contains(
            new byte[] { 50, 60, 50, 60, 50, 60, 50, 60, 40, 50, 60 },
            needle, out i), "mix 5");
        Assert.That(i, Is.EqualTo(6));
    }
    
    [Test]
    public void byte_search_2()
    {
            // ReSharper disable StringLiteralTypo
        var needle = Encoding.ASCII.GetBytes("world");

        Assert.True(HttpHostHeaderRewriter.Contains(needle, needle, out var i), "self");
        Assert.That(i, Is.EqualTo(0));

        Assert.True(HttpHostHeaderRewriter.Contains(
            Encoding.ASCII.GetBytes("wxrlddddworld"),
            needle, out i), "offset 1, end");
        Assert.That(i, Is.EqualTo(8));

        Assert.True(HttpHostHeaderRewriter.Contains(
            Encoding.ASCII.GetBytes("worldddddddd"),
            needle, out i), "offset 2, start");
        Assert.That(i, Is.EqualTo(0));

        Assert.False(HttpHostHeaderRewriter.Contains(
            Encoding.ASCII.GetBytes("hello, wold warld weird"),
            needle, out i), "mix 1");
        Assert.That(i, Is.EqualTo(-1));
        
        Assert.True(HttpHostHeaderRewriter.Contains(
            Encoding.ASCII.GetBytes("rldwoldworldwordworl"),
            needle, out i), "mix 2");
        Assert.That(i, Is.EqualTo(7));
        
        Assert.True(HttpHostHeaderRewriter.Contains(
            Encoding.ASCII.GetBytes("dlorwdlorwdloworldrwdlorwdlorw"),
            needle, out i), "mix 3");
        Assert.That(i, Is.EqualTo(13));
        
        Assert.False(HttpHostHeaderRewriter.Contains(
            Encoding.ASCII.GetBytes("dlorwdlorwdlorwdlorwdlorw"),
            needle, out i), "mix 4");
        Assert.That(i, Is.EqualTo(-1));
        
        Assert.True(HttpHostHeaderRewriter.Contains(
            Encoding.ASCII.GetBytes("Hello, world"),
            needle, out i), "mix 5");
        Assert.That(i, Is.EqualTo(7));
            // ReSharper restore StringLiteralTypo
    }

    [Test]
    public void restore_captured_text()
    {
        const string input = @"payload => 990 bytes
0000: 50 4F 53 54 20 2F 69 50 47 2F 63 32 62 2F 6D 75 POST /iPG/c2b/mu
0016: 6C 74 69 6F 6E 65 20 48 54 54 50 2F 31 2E 31 0D ltione HTTP/1.1.
0032: 0A 41 63 63 65 70 74 3A 20 2A 2F 2A 0D 0A 43 6F .Accept: */*..Co
0048: 6E 74 65 6E 74 2D 54 79 70 65 3A 20 74 65 78 74 ntent-Type: text
0064: 2F 78 6D 6C 0D 0A 48 6F 73 74 3A 20 62 72 6F 6B /xml..Host: brok
0080: 65 72 32 2E 69 70 67 2E 74 7A 2E 76 6F 64 61 66 er2.ipg.tz.vodaf
0096: 6F 6E 65 2E 63 6F 6D 0D 0A 0D 0A 3C 3F 78 6D 6C one.com....<?xml
0112: 20 76 65 72 73 69 6F 6E 3D 22 31 2E 30 22 3F 3E  version=""1.0""?>
0128: 0A 3C 6D 70 65 73 61 42 72 6F 6B 65 72 20 76 65 .<mpesaBroker ve
0144: 72 73 69 6F 6E 3D 22 32 2E 30 22 20 78 6D 6C 6E rsion=""2.0"" xmln
0160: 73 3D 22 68 74 74 70 3A 2F 2F 69 6E 66 6F 77 69 s=""http://infowi
0176: 73 65 2E 63 6F 2E 74 7A 2F 62 72 6F 6B 65 72 2F se.co.tz/broker/
0192: 22 3E 0A 20 20 3C 73 65 72 76 69 63 65 50 72 6F "">.  <servicePro
0208: 76 69 64 65 72 3E 0A 20 20 20 20 3C 73 70 49 64 vider>.    <spId
0224: 3E 37 35 37 30 37 30 3C 2F 73 70 49 64 3E 0A 20 >757070</spId>.
0240: 20 20 20 3C 73 70 50 61 73 73 77 6F 72 64 3E 6B    <spPassword>k
0256: 30 6D 2B 43 43 77 70 51 42 56 6A 41 39 36 53 63 0m+CCwpQBVjA96Sc
0272: 4C 39 4C 44 6C 34 7A 53 4B 6C 33 43 74 79 6D 77 L9LDl4zSKl3Ctymw
0288: 69 78 62 48 4F 42 35 67 66 38 3D 3C 2F 73 70 50 ixbHOB5gf8=</spP
0304: 61 73 73 77 6F 72 64 3E 0A 20 20 20 20 3C 74 69 assword>.    <ti
0320: 6D 65 73 74 61 6D 70 3E 32 30 32 32 31 30 32 37 mestamp>20221027
0336: 30 37 31 36 34 38 3C 2F 74 69 6D 65 73 74 61 6D 071648</timestam
0352: 70 3E 0A 20 20 3C 2F 73 65 72 76 69 63 65 50 72 p>.  </servicePr
0368: 6F 76 69 64 65 72 3E 0A 20 20 3C 74 72 61 6E 73 ovider>.  <trans
0384: 61 63 74 69 6F 6E 3E 0A 20 20 20 20 3C 72 65 73 action>.    <res
0400: 75 6C 74 54 79 70 65 3E 46 61 69 6C 65 64 3C 2F ultType>Failed</
0416: 72 65 73 75 6C 74 54 79 70 65 3E 0A 20 20 20 20 resultType>.
0432: 3C 72 65 73 75 6C 74 43 6F 64 65 3E 39 39 39 3C <resultCode>999<
0448: 2F 72 65 73 75 6C 74 43 6F 64 65 3E 0A 20 20 20 /resultCode>.
0464: 20 3C 72 65 73 75 6C 74 44 65 73 63 3E 54 72 61  <resultDesc>Tra
0480: 6E 73 61 63 74 69 6F 6E 20 27 49 6E 69 74 69 61 nsaction 'Initia
0496: 74 6F 72 27 20 64 69 64 20 6E 6F 74 20 6D 61 74 tor' did not mat
0512: 63 68 20 61 20 72 65 67 69 73 74 65 72 65 64 20 ch a registered
0528: 75 73 65 72 3C 2F 72 65 73 75 6C 74 44 65 73 63 user</resultDesc
0544: 3E 0A 20 20 20 20 3C 73 65 72 76 69 63 65 52 65 >.    <serviceRe
0560: 63 65 69 70 74 3E 39 4A 52 36 38 34 51 47 4F 43 ceipt>9JR684QGOC
0576: 36 3C 2F 73 65 72 76 69 63 65 52 65 63 65 69 70 6</serviceReceip
0592: 74 3E 0A 20 20 20 20 3C 73 65 72 76 69 63 65 44 t>.    <serviceD
0608: 61 74 65 3E 32 30 32 32 2D 31 30 2D 32 37 20 31 ate>2022-10-27 1
0624: 30 3A 31 36 3A 34 35 3C 2F 73 65 72 76 69 63 65 0:16:45</service
0640: 44 61 74 65 3E 0A 20 20 20 20 3C 6F 72 69 67 69 Date>.    <origi
0656: 6E 61 74 6F 72 43 6F 6E 76 65 72 73 61 74 69 6F natorConversatio
0672: 6E 49 44 3E 37 61 62 31 34 62 35 32 33 30 34 36 nID>7ab14b523046
0688: 34 35 36 31 62 63 39 30 64 63 65 63 38 65 31 61 4561bc90dcec8e1a
0704: 62 30 63 64 3C 2F 6F 72 69 67 69 6E 61 74 6F 72 b0cd</originator
0720: 43 6F 6E 76 65 72 73 61 74 69 6F 6E 49 44 3E 0A ConversationID>.
0736: 20 20 20 20 3C 63 6F 6E 76 65 72 73 61 74 69 6F     <conversatio
0752: 6E 49 44 3E 39 4A 52 36 38 34 51 47 4F 43 36 3C nID>9JR684QGOC6<
0768: 2F 63 6F 6E 76 65 72 73 61 74 69 6F 6E 49 44 3E /conversationID>
0784: 0A 20 20 20 20 3C 74 72 61 6E 73 61 63 74 69 6F .    <transactio
0800: 6E 49 44 3E 37 37 31 35 39 35 38 32 37 5F 37 35 nID>771595827_75
0816: 37 30 37 30 3C 2F 74 72 61 6E 73 61 63 74 69 6F 7070</transactio
0832: 6E 49 44 3E 0A 20 20 20 20 3C 69 6E 69 74 69 61 nID>.    <initia
0848: 74 6F 72 3E 69 62 6D 5F 69 6E 3C 2F 69 6E 69 74 tor>ibm_in</init
0864: 69 61 74 6F 72 3E 0A 20 20 20 20 3C 69 6E 69 74 iator>.    <init
0880: 69 61 74 6F 72 50 61 73 73 77 6F 72 64 3E 5A 31 iatorPassword>Z1
0896: 30 31 44 61 46 2B 42 49 4E 62 53 47 58 54 6C 53 01DaF+BINbSGXTlS
0912: 75 76 33 2F 33 68 62 4C 56 79 30 55 45 58 58 4E uv3/3hbLVy0UEXXN
0928: 4D 76 44 43 6B 44 57 52 41 3D 3C 2F 69 6E 69 74 MvDCkDWRA=</init
0944: 69 61 74 6F 72 50 61 73 73 77 6F 72 64 3E 0A 20 iatorPassword>.
0960: 20 3C 2F 74 72 61 6E 73 61 63 74 69 6F 6E 3E 0A  </transaction>.
0976: 3C 2F 6D 70 65 73 61 42 72 6F 6B 65 72 3E       </mpesaBroker>
";
        
        // skip lines before "0000:..."
        // Take fixed centre section, break by spaces, parse hex.
        var lines = input.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var result = new List<byte>();
        
        var on = false;
        foreach (var line in lines)
        {
            if (line.StartsWith("0000:")) on = true;
            if (!on) continue;

            var byteChars = string.Join("", line.Skip(6).Take(47));
            var bytes = byteChars.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            foreach (var str in bytes)
            {
                result.Add((byte)int.Parse(str, NumberStyles.HexNumber));
            }
        }

        Console.Write(Encoding.UTF8.GetString(result.ToArray()));
    }
}
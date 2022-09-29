using NUnit.Framework;
using VirtualVpn;
using VirtualVpn.InternetProtocol;

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
}
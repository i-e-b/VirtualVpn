using NUnit.Framework;
using VirtualVpn;

namespace ProtocolTests;

[TestFixture]
public class SmallTests
{
    [Test]
    public void enum_ordering_works()
    {
        Assert.True(LogLevel.Trace < LogLevel.Crypto, "enum order");
    }
}
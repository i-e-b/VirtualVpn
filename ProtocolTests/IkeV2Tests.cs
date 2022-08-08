using NUnit.Framework;
using RawSocketTest;
using SkinnyJson;

namespace ProtocolTests;

[TestFixture]
public class IkeV2Tests
{
    [Test]
    public void can_read_initiator()
    {
        Json.DefaultParameters.EnableAnonymousTypes = true;
        var bytes = File.ReadAllBytes("SampleData/IkeV2_message1.bin");
        
        var ikeMessage = IkeMessage.FromBytes(bytes, 0);
        ikeMessage.ReadPayloads(null);
        
        var str = Json.Beautify(Json.Freeze(ikeMessage));
        Console.WriteLine(str);
    }

    [Test]
    public void our_first_reply_makes_sense()
    {
        var bytes = File.ReadAllBytes("SampleData/IKEv2-Reply_-1_Port-500_IKE.bin");
        
        var ikeMessage = IkeMessage.FromBytes(bytes, 0);
        ikeMessage.ReadPayloads(null);
        
        var str = Json.Beautify(Json.Freeze(ikeMessage));
        Console.WriteLine(str);
    }
}
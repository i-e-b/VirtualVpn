using System.Net;
using NUnit.Framework;
using SkinnyJson;
using VirtualVpn;
using VirtualVpn.EspProtocol;
using VirtualVpn.Helpers;
using VirtualVpn.InternetProtocol;
#pragma warning disable CS8602

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
        ikeMessage.ReadPayloadChain(null);
        
        var str = Json.Beautify(Json.Freeze(ikeMessage));
        Console.WriteLine(str);
    }

    [Test]
    public void our_first_reply_makes_sense()
    {
        var bytes = File.ReadAllBytes("SampleData/IKEv2-Reply_-1_Port-500_IKE.bin");
        
        var ikeMessage = IkeMessage.FromBytes(bytes, 0);
        ikeMessage.ReadPayloadChain(null);
        
        var str = Json.Beautify(Json.Freeze(ikeMessage));
        Console.WriteLine(str);
    }

    [Test]
    public void start_up_messages()
    {
        // Mostly the flip of HandleSaInit
        // To start with, display the StrongSwan 1st payload
        
        var bytes = File.ReadAllBytes("SampleData/UpAndDown/IKEv2-0_Port-500_IKE.bin");
        
        var ikeMessage = IkeMessage.FromBytes(bytes, 0);
        ikeMessage.ReadPayloadChain(null);
        
        Console.WriteLine("\r\n--------------------------------------------------------------------------------");
        
        // we only support AES CBC mode at the moment, and M-Pesa only does DH-14
        Console.WriteLine(TypeDescriber.Describe(ikeMessage));
        
        
        // ENCR id=EncryptionTypeId.ENCR_AES_CBC attr=[KEY_LENGTH: 256]
        
        var gateway = IpV4Address.Localhost;
        var testUdpServer = new TestUdpServer();
        var newSession = new VpnSession(gateway, testUdpServer, new TestSessionHost(), weAreInitiator:true, 0);
        newSession.RequestNewSession(gateway.MakeEndpoint(port:500));
        
        Assert.That(testUdpServer.SentMessages.Count, Is.EqualTo(1), "Message count");
        
        var ourMessage = IkeMessage.FromBytes(testUdpServer.SentMessages[0], 0);
        ourMessage.ReadPayloadChain(null);
        
        Console.WriteLine("--------------------------------------------------------------------------------");
        
        // we only support AES CBC mode at the moment, and M-Pesa only does DH-14
        Console.WriteLine(TypeDescriber.Describe(ourMessage));
        
        Assert.That(ourMessage.SpiI, Is.Not.Zero, "Initiator SPI");
        Assert.That(ourMessage.SpiR, Is.Zero, "Gap for responder SPI");
        
        
        Assert.Inconclusive("not yet tested");
    }
}

public class TestUdpServer : IUdpServer
{
    public readonly List<byte[]> SentMessages = new ();
    
    public void SendRaw(byte[] message, IPEndPoint to)
    {
        SentMessages.Add(message);
    }
}

public class TestSessionHost : ISessionHost
{
    public void AddChildSession(ChildSa childSa) { throw new NotImplementedException(); }
    public void RemoveChildSession(params uint[] spis) { throw new NotImplementedException(); }
    public void RemoveSession(bool wasRemoteRequest, params ulong[] spis) { throw new NotImplementedException(); }
    public string StatusToString() { throw new NotImplementedException(); }
    public void ConnectionNormal() { }
    public void ConnectionRemoteTerminated(IpV4Address gateway) { }
    public void SetLastKeepAlive(IpV4Address gateway) { }
}
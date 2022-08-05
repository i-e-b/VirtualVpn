using NUnit.Framework;
using RawSocketTest;
using RawSocketTest.Payloads;
#pragma warning disable CS8602

namespace ProtocolTests;

[TestFixture]
public class PayloadSerialisationTests
{
    [Test]
    public void KeyExchange_round_trip()
    {
        // set values
        var publicKey = new byte[] { 1, 2, 4, 8 };
        var original = new PayloadKeyExchange(DhId.DH_14, publicKey) {
            NextPayload = PayloadType.CERTREQ
        };

        // serialise
        Console.WriteLine($"Original requires {original.Size} bytes");
        var buffer = new byte[original.Size];
        var written = original.WriteBytes(buffer, 0);
        
        Assert.That(written, Is.EqualTo(original.Size), "Written bytes did not match declared size");
        
        // deserialise
        var idx = 0;
        var nextType = original.Type; // must be correct, or will get wrong wrapper
        var raw = IkeMessage.ReadPayload(buffer, null, ref idx, ref nextType);
        var restored = raw as PayloadKeyExchange;
        
        Assert.That(restored, Is.Not.Null, $"Did not read payload correctly -- type was {raw.GetType()}");
        Assert.That(nextType, Is.EqualTo(PayloadType.CERTREQ), "Payload NEXT type was wrong");
        Assert.That(restored.Type, Is.EqualTo(PayloadType.KE), "Payload type was wrong");
        Assert.That(idx, Is.EqualTo(written), "Not all bytes written were read"); // needs to be correct, otherwise the offset is wrong for next payload
        Assert.That(restored.Size, Is.EqualTo(original.Size), "Original and restored disagree on serialisation size");
        
        // check values
        Assert.That(restored.Type, Is.EqualTo(original.Type), "Type");
        Assert.That(restored.KeyData, Is.EqualTo(original.KeyData).AsCollection, "KeyData");
        Assert.That(restored.DiffieHellmanGroup, Is.EqualTo(original.DiffieHellmanGroup), "DH Group");
    }
}
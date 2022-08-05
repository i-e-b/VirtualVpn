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
        Assert.That(restored.Data, Is.EqualTo(original.Data).AsCollection, "Raw data does not match");
        
        // check values
        Assert.That(restored.Type, Is.EqualTo(original.Type), "Type");
        Assert.That(restored.KeyData, Is.EqualTo(original.KeyData).AsCollection, "KeyData");
        Assert.That(restored.DiffieHellmanGroup, Is.EqualTo(original.DiffieHellmanGroup), "DH Group");
    }
    
    [Test]
    public void Nonce_round_trip()
    {
        // set values
        var nonce = new byte[] { 1, 2, 4, 8 };
        var original = new PayloadNonce(nonce) {
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
        var restored = raw as PayloadNonce;
        
        Assert.That(restored, Is.Not.Null, $"Did not read payload correctly -- type was {raw.GetType()}");
        Assert.That(nextType, Is.EqualTo(PayloadType.CERTREQ), "Payload NEXT type was wrong");
        Assert.That(restored.Type, Is.EqualTo(PayloadType.NONCE), "Payload type was wrong");
        Assert.That(idx, Is.EqualTo(written), "Not all bytes written were read"); // needs to be correct, otherwise the offset is wrong for next payload
        Assert.That(restored.Size, Is.EqualTo(original.Size), "Original and restored disagree on serialisation size");
        
        // check values
        Assert.That(restored.Type, Is.EqualTo(original.Type), "Type");
        Assert.That(restored.Data, Is.EqualTo(original.Data).AsCollection, "Data");
    }
    
    [Test]
    public void Notify_round_trip()
    {
        // set values
        var spi = new byte[] { 1, 2, 4, 8 };
        var data = new byte[] { 16, 32, 64, 128 };
        var original = new PayloadNotify(IkeProtocolType.ESP, NotifyId.COOKIE, spi, data) {
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
        var restored = raw as PayloadNotify;
        
        Assert.That(restored, Is.Not.Null, $"Did not read payload correctly -- type was {raw.GetType()}");
        Assert.That(nextType, Is.EqualTo(PayloadType.CERTREQ), "Payload NEXT type was wrong");
        Assert.That(restored.Type, Is.EqualTo(PayloadType.NOTIFY), "Payload type was wrong");
        Assert.That(idx, Is.EqualTo(written), "Not all bytes written were read"); // needs to be correct, otherwise the offset is wrong for next payload
        Assert.That(restored.Size, Is.EqualTo(original.Size), "Original and restored disagree on serialisation size");
        Assert.That(restored.Data, Is.EqualTo(original.Data).AsCollection, "Raw data does not match");
        
        // check values
        Assert.That(restored.Type, Is.EqualTo(original.Type), "Type");
        Assert.That(restored.NotificationType, Is.EqualTo(original.NotificationType), "NotificationType");
        Assert.That(restored.ProtocolType, Is.EqualTo(original.ProtocolType), "ProtocolType");
        Assert.That(restored.SpiSize, Is.EqualTo(original.SpiSize), "SpiSize");
        Assert.That(restored.InfoData, Is.EqualTo(original.InfoData).AsCollection, "InfoData");
        Assert.That(restored.SpiData, Is.EqualTo(original.SpiData).AsCollection, "SpiData");
    }
    
    [Test]
    public void SecurityAssociation_round_trip()
    {
        // set values
        #region input data
        var spi = new byte[] { 1, 2, 4, 8 };
        var transforms = new List<Transform>
        {
            new() {
                Type = TransformType.DH,
                Id = 456,
            },
            new() {
                Type = TransformType.ESN,
                Id = 123,
                Attributes =
                {
                    new TransformAttribute(TransformAttr.PRF, 555),
                    new TransformAttribute(TransformAttr.ENCR, new byte[] { 8, 7, 6, 5 })
                }
            }
        };

        var proposal = new Proposal{
            Number = 1,
            Protocol = IkeProtocolType.IKE,
            SpiData = spi,
            SpiSize = (byte)spi.Length,
            Transforms = transforms,
            TransformCount = (byte)transforms.Count
        };
        #endregion
        
        var original = new PayloadSa(proposal) {
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
        var restored = raw as PayloadSa;
        
        Assert.That(restored, Is.Not.Null, $"Did not read payload correctly -- type was {raw.GetType()}");
        Assert.That(nextType, Is.EqualTo(PayloadType.CERTREQ), "Payload NEXT type was wrong");
        Assert.That(restored.Type, Is.EqualTo(PayloadType.SA), "Payload type was wrong");
        Assert.That(idx, Is.EqualTo(written), "Not all bytes written were read"); // needs to be correct, otherwise the offset is wrong for next payload
        Assert.That(restored.Size, Is.EqualTo(original.Size), "Original and restored disagree on serialisation size");
        Assert.That(restored.Data, Is.EqualTo(original.Data).AsCollection, "Raw data does not match");
        
        // check values
        Assert.That(restored.Type, Is.EqualTo(original.Type), "Type");
        Assert.That(restored.Proposals, Is.EqualTo(original.Proposals).AsCollection, "Proposals"); // TODO: need to deep inspect this properly
    }
}
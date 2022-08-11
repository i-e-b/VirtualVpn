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
        var raw = IkeMessage.ReadSinglePayload(buffer, null, ref idx, ref nextType).Single();
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
        var raw = IkeMessage.ReadSinglePayload(buffer, null, ref idx, ref nextType).Single();
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
        var raw = IkeMessage.ReadSinglePayload(buffer, null, ref idx, ref nextType).Single();
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
        var raw = IkeMessage.ReadSinglePayload(buffer, null, ref idx, ref nextType).Single();
        var restored = raw as PayloadSa;
        
        Assert.That(restored, Is.Not.Null, $"Did not read payload correctly -- type was {raw.GetType()}");
        Assert.That(nextType, Is.EqualTo(PayloadType.CERTREQ), "Payload NEXT type was wrong");
        Assert.That(restored.Type, Is.EqualTo(PayloadType.SA), "Payload type was wrong");
        Assert.That(idx, Is.EqualTo(written), "Not all bytes written were read"); // needs to be correct, otherwise the offset is wrong for next payload
        Assert.That(restored.Size, Is.EqualTo(original.Size), "Original and restored disagree on serialisation size");
        Assert.That(restored.Data, Is.EqualTo(original.Data).AsCollection, "Raw data does not match");
        
        // check values
        Assert.That(restored.Type, Is.EqualTo(original.Type), "Type");
        
        Assert.That(restored.Proposals.Count, Is.EqualTo(original.Proposals.Count), "Proposals .Count");
        #region Proposal deep value testing
        for (int i = 0; i < original.Proposals.Count; i++)
        {
            var r = restored.Proposals[i];
            var o = original.Proposals[i];
            
            Assert.That(r.Number, Is.EqualTo(o.Number), $"Proposal {i}: Number");
            Assert.That(r.Protocol, Is.EqualTo(o.Protocol), $"Proposal {i}: Protocol");
            Assert.That(r.Size, Is.EqualTo(o.Size), $"Proposal {i}: Size");
            
            Assert.That(r.SpiSize, Is.EqualTo(o.SpiSize), $"Proposal {i}: SpiSize");
            Assert.That(r.SpiData, Is.EqualTo(o.SpiData).AsCollection, $"Proposal {i}: SpiData");
            
            Assert.That(r.TransformCount, Is.EqualTo(o.TransformCount), $"Proposal {i}: TransformCount");
            Assert.That(r.Transforms.Count, Is.EqualTo(o.Transforms.Count), $"Proposal {i}: Transforms .Count");
            for (int j = 0; j < o.Transforms.Count; j++)
            {
                var rt = r.Transforms[j];
                var ot = o.Transforms[j];
                
                Assert.That(rt.Id, Is.EqualTo(ot.Id), $"Proposal {i}, Transform {j}: Id");
                Assert.That(rt.Length, Is.EqualTo(ot.Length), $"Proposal {i}, Transform {j}: Length");
                Assert.That(rt.Size, Is.EqualTo(ot.Size), $"Proposal {i}, Transform {j}: Size");
                Assert.That(rt.Type, Is.EqualTo(ot.Type), $"Proposal {i}, Transform {j}: Type");
                Assert.That(rt.Attributes.Count, Is.EqualTo(ot.Attributes.Count), $"Proposal {i}, Transform {j}: Attributes.Count");

                for (int k = 0; k < ot.Attributes.Count; k++)
                {
                    var ra = rt.Attributes[k];
                    var oa = ot.Attributes[k];
                    
                    Assert.That(ra.Size, Is.EqualTo(oa.Size), $"Proposal {i}, Transform {j}, Attribute {k}: Size");
                    Assert.That(ra.Type, Is.EqualTo(oa.Type), $"Proposal {i}, Transform {j}, Attribute {k}: Type");
                    Assert.That(ra.Value, Is.EqualTo(oa.Value), $"Proposal {i}, Transform {j}, Attribute {k}: Value");
                    Assert.That(ra.ValueBytes, Is.EqualTo(oa.ValueBytes).AsCollection, $"Proposal {i}, Transform {j}, Attribute {k}: ValueBytes");
                }
            }
        }
        #endregion
    }
    
    [Test]
    public void VendorId_round_trip()
    {
        // set values
        var original = new PayloadVendorId("test vendor id") {
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
        var raw = IkeMessage.ReadSinglePayload(buffer, null, ref idx, ref nextType).Single();
        var restored = raw as PayloadVendorId;
        
        Assert.That(restored, Is.Not.Null, $"Did not read payload correctly -- type was {raw.GetType()}");
        Assert.That(nextType, Is.EqualTo(PayloadType.CERTREQ), "Payload NEXT type was wrong");
        Assert.That(restored.Type, Is.EqualTo(PayloadType.VENDOR), "Payload type was wrong");
        Assert.That(idx, Is.EqualTo(written), "Not all bytes written were read"); // needs to be correct, otherwise the offset is wrong for next payload
        Assert.That(restored.Size, Is.EqualTo(original.Size), "Original and restored disagree on serialisation size");
        
        // check values
        Assert.That(restored.Type, Is.EqualTo(original.Type), "Type");
        Assert.That(restored.Data, Is.EqualTo(original.Data).AsCollection, "Data");
        
        Assert.That(restored.Description, Is.EqualTo(original.Description), "Description");
    }
}
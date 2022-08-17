using NUnit.Framework;
using RawSocketTest.Crypto;
using RawSocketTest.Enums;
using RawSocketTest.Helpers;

namespace ProtocolTests;

[TestFixture]
public class KeyExchangeTests
{
    [Test]
    public void comparing_secret_generators()
    {
        var alice = BCDiffieHellman.CreateForGroup(DhId.DH_14) ?? throw new Exception("Failed to generate Alice");
        alice.get_our_public_key(out var alicePublicKey);
        
        var bob = BCDiffieHellman.CreateForGroup(DhId.DH_14) ?? throw new Exception("Failed to generate Bob");
        bob.get_our_public_key(out var bobPublicKey);
        
        alice.set_their_public_key(bobPublicKey);
        bob.set_their_public_key(alicePublicKey);
        
        alice.get_shared_secret(out var aliceSecret);
        bob.get_shared_secret(out var bobSecret);
        
        Console.WriteLine(Bit.Describe("alice", aliceSecret));
        Console.WriteLine(Bit.Describe("bob", bobSecret));
        
        Assert.That(bobSecret.Length, Is.GreaterThan(0), "Secret is empty");
        
        Assert.That(aliceSecret, Is.EqualTo(bobSecret).AsCollection, "secrets match");
    }
}
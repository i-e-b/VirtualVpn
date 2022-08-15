using NUnit.Framework;
using RawSocketTest;
using RawSocketTest.Crypto;
using RawSocketTest.gmpDh;
using RawSocketTest.Helpers;

namespace ProtocolTests;

[TestFixture]
public class KeyExchangeTests
{

    [Test] // NOTE: due to a bug in the NuGet package, you probably need to copy the 'native' library into the bin folder.
    public void comparing_secret_generators__gmp_vs_gmp()
    {
        var alice = GmpDiffieHellman.CreateForGroup(DhId.DH_14) ?? throw new Exception("Failed to generate Alice");
        alice.get_our_public_key(out var alicePublicKey);
        
        var bob = GmpDiffieHellman.CreateForGroup(DhId.DH_14) ?? throw new Exception("Failed to generate Bob");
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
    
    
    [Test] // NOTE: due to a bug in the NuGet package, you probably need to copy the 'native' library into the bin folder.
    public void comparing_secret_generators__gmp_vs_bc()
    {
        var alice = BCDiffieHellman.CreateForGroup(DhId.DH_14) ?? throw new Exception("Failed to generate Alice");
        alice.get_our_public_key(out var alicePublicKey);
        
        var bob = GmpDiffieHellman.CreateForGroup(DhId.DH_14) ?? throw new Exception("Failed to generate Bob");
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
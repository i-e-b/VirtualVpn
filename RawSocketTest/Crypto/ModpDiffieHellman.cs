using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using RawSocketTest.gmpDh;
using static System.Numerics.BigInteger;

namespace RawSocketTest.Crypto;

public class ModpDiffieHellman
{
    
/*
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 1999, 2000, 2001  Henry Spencer.
 * Copyright (C) 2010 Tobias Brunner
 * Copyright (C) 2005-2008 Martin Willi
 * Copyright (C) 2005 Jan Hutter
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

    /**
	 * Diffie Hellman group number.
	 */
    DhId group;

    /*
     * Generator value.
     */
    BigInteger g;

    /**
	 * My private value.
	 */
    BigInteger xa;

    /**
	 * My public value.
	 */
    BigInteger ya;

    /**
	 * Other public value.
	 */
    BigInteger yb;

    /**
	 * Shared secret.
	 */
    BigInteger zz;

    /**
	 * Modulus.
	 */
    BigInteger p;

    /**
	 * Modulus length.
	 */
    int p_len;

    /**
	 * True if shared secret is computed and stored in my_public_value.
	 */
    bool computed;

    public bool set_their_public_key(byte[] value)
    {
        BigInteger p_min_1 = p - 1;

        if (!key_exchange_verify_pubkey(group, value)) // check the length is valid
        {
            return false;
        }

        //mpz_init(p_min_1);
        //mpz_sub_ui(p_min_1, this.p, 1);

        /* this->computed is not reset in order to prevent reuse of this DH
         * instance (see below) */
        //mpz_import(this.yb, (size_t)value.Length, 1, 1, 1, 0, data);
        import(ref yb, value);

        /* check that the public value y satisfies 1 < y < p-1.
         * according to RFC 6989, section 2.1, this is enough for the common safe-
         * prime DH groups (i.e. with q=(p-1)/2 being prime), only for those with
         * small subgroups (22, 23, 24) does the RFC require the extended test but
         * only if private keys are reused. we never do that anyway and it's
         * explicitly prevented in this implementation. so the extended test, which
         * optionally happens in get_shared_secret(), is really only useful for full
         * NIST SP 800-56A compliance, which only allows the partial check for
         * safe-prime groups.
         */
        //if (mpz_cmp_ui(yb, 1) <= 0 || mpz_cmp(yb, p_min_1) >= 0)
        if (yb < 1 || p_min_1 < yb)
        {
            DebugLog("public DH value verification failed: ", "y <= 1 || y >= p - 1");
            return false;
        }

        return true;
    }

    private static void DebugLog(params string[] msgs)
    {
        Log.Debug(msgs);
    }

    private bool key_exchange_verify_pubkey(DhId dhId, byte[] value)
    {
        switch (dhId)
        {
            case DhId.DH_NONE:
                return false;

            case DhId.DH_1:
            case DhId.DH_2:
            case DhId.DH_5:
            case DhId.DH_14:
            case DhId.DH_15:
            case DhId.DH_16:
            case DhId.DH_17:
            case DhId.DH_18:
            case DhId.DH_22:
            case DhId.DH_23:
            case DhId.DH_24:
            {
                var settings = GmpDhParameters.diffie_hellman_get_params(group);
                if (settings is null) return false;
                return (value.Length == settings.Value.prime.Length);
            }

            case DhId.DH_19:
            case DhId.DH_20:
            case DhId.DH_21:
            case DhId.DH_25:
            case DhId.DH_26:
            case DhId.DH_27:
            case DhId.DH_28:
            case DhId.DH_29:
            case DhId.DH_30:
            case DhId.DH_31:
            case DhId.DH_32:
                return true; // todo: check. See src/libstrongswan/crypto/key_exchange.c:547
            default:
                throw new ArgumentOutOfRangeException(nameof(dhId), dhId, null);
        }
    }

    public bool get_our_public_key(out byte[] result)
    {
        result = export(ya);
        
        var pad = 256 - result.Length;
        
        if (pad < 1) return true;
        
        result = (new byte[pad]).Concat(result).ToArray();
        return true;
    }

    private static byte[] export(BigInteger src)
    {
        return src.ToByteArray(isUnsigned: false, isBigEndian: true);
    }

//METHOD(key_exchange_t, set_private_key, bool, private_gmp_diffie_hellman_t *this, chunk_t value)
    public bool set_private_key(byte[] value)
    {
        //mpz_import(xa, value.len, 1, 1, 1, 0, value.ptr);
        import(ref xa, value);
        
        ya = ModPow(g, xa, p);
        
        //mpz_powm(ya, g, xa, p);
        computed = false;
        return true;
    }

    private static void import(ref BigInteger target, byte[] value)
    {
        target = new BigInteger(value, isUnsigned: false, isBigEndian:true);
        /*
        var data = allocate((size_t)value.Length);
        Marshal.Copy(value, 0, data.ToIntPtr(), value.Length);
        mpz_import(target, (size_t)value.Length, 1, 1, 1, 0, data);
        free(data);*/
    }

//METHOD(key_exchange_t, get_shared_secret, bool, private_gmp_diffie_hellman_t *this, chunk_t *secret)
    public bool get_shared_secret(out byte[] secret)
    {
        secret = Array.Empty<byte>(); // default in case of failure
        if (!computed)
        {
            /* test if y ^ q mod p = 1, where q = (p - 1)/2 or the actual size of
             * the subgroup.  as noted above, this check is not really necessary as
             * the plugin does not reuse private keys */

            var one = One;//new mpz_t();
            var q = Zero;//new mpz_t();
            var p_min_1 = Zero;//new mpz_t();
            //mpz_init(q);
            //mpz_init(one);

            var dh_params = GmpDhParameters.diffie_hellman_get_params(group) ?? throw new Exception($"DH group not supported: {group.ToString()}");

            if (dh_params.subgroup.Length <= 0)
            {
                //mpz_init(p_min_1);
                //mpz_sub_ui(p_min_1, p, 1);
                p_min_1 = p - 1;
                
                //mpz_fdiv_q_2exp(q, p_min_1, 1);
                // var d = BigInteger.Pow(2, 1); // technically, this is what the '2exp' is doing?
                q = p_min_1 / 2;
                
                //mpz_clear(p_min_1);
                p_min_1 = Zero;
            }
            else
            {
                import(ref q, dh_params.subgroup);
                //mpz_import(q, params->subgroup.len, 1, 1, 1, 0, params->subgroup.ptr);
            }

            one = ModPow(yb, q, p);
            //mpz_powm(one, yb, q, p);
            //mpz_clear(q);
            if (one != 1)
            {
                DebugLog("public DH value verification failed: ", "y ^ q mod p != 1");
                //mpz_clear(one);
                return true;
            }

            //mpz_clear(one);

            //mpz_powm(zz, yb, xa, p);
            zz = ModPow(yb,xa,p);
            computed = true;
        }

        secret = export(zz);
        return true;
    }

//METHOD(key_exchange_t, get_method, key_exchange_method_t, private_gmp_diffie_hellman_t *this)
    public DhId get_method()
    {
        return group;
    }

//METHOD(key_exchange_t, destroy, void, private_gmp_diffie_hellman_t *this)
    public void destroy()
    {
        //mpz_clear(p);
        //mpz_clear(xa);
        //mpz_clear(ya);
        //mpz_clear(yb);
        //mpz_clear(zz);
        //mpz_clear(g);
    }

    public ModpDiffieHellman()
    {
        group = DhId.None;
        g = Zero;//new mpz_t();
        xa = Zero;//new mpz_t();
        ya = Zero;//new mpz_t();
        yb = Zero;//new mpz_t();
        zz = Zero;//new mpz_t();
        p = Zero;//new mpz_t();
        p_len = 0;//(size_t)0;
    }


    /**
 * Generic internal constructor
 */
//static gmp_diffie_hellman_t *create_generic(key_exchange_method_t group, size_t exp_len, chunk_t g, chunk_t p)
    public ModpDiffieHellman(DhId group_, int exp_len_, byte[] g_, byte[] p_)
    {
        group = group_;
        p_len = p_.Length;

        g = Zero;//new mpz_t();
        xa = Zero;//new mpz_t();
        ya = Zero;//new mpz_t();
        yb = Zero;//new mpz_t();
        zz = Zero;//new mpz_t();
        p = Zero;//new mpz_t();
        p_len = 0;//(size_t)0;

        //mpz_init(p);
        //mpz_init(yb);
        //mpz_init(ya);
        //mpz_init(xa);
        //mpz_init(zz);
        //mpz_init(g);

        //mpz_import(this->g, g.len, 1, 1, 1, 0, g.ptr);
        //mpz_import(this->p, p.len, 1, 1, 1, 0, p.ptr);
        import(ref g, g_);
        import(ref p, p_);

        var random = new byte[exp_len_];
        RandomNumberGenerator.Fill(random);
        /*if (!rng->allocate_bytes(rng, exp_len, &random))
        {
            DBG1(DBG_LIB, "failed to allocate DH secret");
            rng->destroy(rng);
            destroy(this);
            return NULL;
        }
        rng->destroy(rng);*/

        if (exp_len_ == p_len)
        {
            /* achieve bitsof(p)-1 by setting MSB to 0 */
            //*random.ptr &= 0x7F;
            random[0] &= 0x7F;
        }

        //mpz_import(this->xa, random.len, 1, 1, 1, 0, random.ptr);
        import(ref xa, random);

        //chunk_clear(&random);
        for (int i = 0; i < random.Length; i++)
        {
            random[i] = 0;
        }

        DebugLog("        size of DH secret exponent (bits): ", xa.GetBitLength().ToString());

        if (p < 0) p = Negate(p);
        ya = ModPow(g,xa,p);
        //mpz_powm(ya, g, xa, p);
    }

    /// <summary>
    /// Create a new key exchanger based on standard parameters
    /// </summary>
    public static ModpDiffieHellman? CreateForGroup(DhId group)
    {
        var parameters = GmpDhParameters.diffie_hellman_get_params(group);
        if (parameters is null)
        {
            return null;
        }

        return new ModpDiffieHellman(group, (int)parameters.Value.exp_len, parameters.Value.generator, parameters.Value.prime);
    }


    public void Dispose()
    {
        destroy();
        GC.SuppressFinalize(this);
    }
}
using System.Security.Cryptography;
using RawSocketTest.Enums;

// ReSharper disable InconsistentNaming

namespace RawSocketTest.Crypto;

public class BCDiffieHellman
{
    // ReSharper disable CommentTypo
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
    // ReSharper restore CommentTypo


    /**
	 * Diffie Hellman group number.
	 */
    private readonly DhId group;

    /**
	 * Modulus.
	 */
    private readonly BigInt p;

    /**
	 * My private value.
	 */
    private readonly BigInt xa;

    /**
	 * My public value.
	 */
    private readonly BigInt ya;

    /**
	 * Other side public value.
	 */
    private BigInt yb;

    /**
	 * Shared secret.
	 */
    private BigInt zz;


    /**
	 * True if shared secret is computed and stored in my_public_value.
	 */
    bool computed;

//METHOD(key_exchange_t, set_public_key, bool, private_gmp_diffie_hellman_t *this, chunk_t value)
    public bool set_their_public_key(byte[] value)
    {
        if (!VerifyPublicKey(group, value)) // check the length is valid
        {
            return false;
        }

        //mpz_init(p_min_1);
        var p_min_1 = p.subtract(1); //new BigInt();
        //mpz_sub_ui(p_min_1, this.p, 1);
        /* this->computed is not reset in order to prevent reuse of this DH
         * instance (see below) */
        //mpz_import(this.yb, (size_t)value.Length, 1, 1, 1, 0, data);
        import(out yb, value);

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
        if (yb.compareTo(1) <= 0 || yb.compareTo(p_min_1) >= 0)
        {
            DebugLog("public DH value verification failed: ", "y <= 1 || y >= p - 1");
            //mpz_clear(p_min_1);
            return false;
        }

        //mpz_clear(p_min_1);
        return true;
    }

    private static void DebugLog(params string[] messages)
    {
        Log.Debug(messages);
    }

    private bool VerifyPublicKey(DhId dhId, byte[] value)
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
                var settings = DiffieHellmanParameters.GetParametersForGroup(group);
                if (settings is null) return false;
                return (value.Length == settings.Prime.Length);
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

    private static byte[] export(BigInt src)
    {
        var tmp = src.toByteArray(); // this can leave a zero byte at the top
        
        return tmp[0] == 0 ? tmp.Skip(1).ToArray() : tmp;
    }

    private static void import(out BigInt target, byte[] value)
    {
        target = new BigInt(value);
    }

    public bool get_shared_secret(out byte[] secret)
    {
        secret = Array.Empty<byte>(); // default in case of failure
        if (!computed)
        {
            /* test if y ^ q mod p = 1, where q = (p - 1)/2 or the actual size of
             * the subgroup.  as noted above, this check is not really necessary as
             * the plugin does not reuse private keys */

            BigInt q;

            var dh_params = DiffieHellmanParameters.GetParametersForGroup(group) ?? throw new Exception($"DH group not supported: {group.ToString()}");

            if (dh_params.SubGroup.Length <= 0)
            {
                var p_min_1 = p.subtract(1);
                q = p_min_1.divide(2);
            }
            else
            {
                import(out q, dh_params.SubGroup);
            }

            var one = yb.modPow(q, p);
            if (one.compareTo(1) != 0)
            {
                DebugLog("public DH value verification failed: ", "y ^ q mod p != 1");
                return true;
            }

            zz = yb.modPow(xa,p);
            computed = true;
        }

        secret = export(zz);
        return true;
    }

    /**
 * Generic internal constructor
 */
    public BCDiffieHellman(DhId group_, int exp_len_, byte[] g_, byte[] p_)
    {
        group = group_;

        xa = 0;
        ya = 0;
        yb = 0;
        zz = 0;
        p = 0;
        var pLen = 0;
        import(out var g, g_);
        import(out p, p_);

        var random = new byte[exp_len_];
        RandomNumberGenerator.Fill(random);

        if (exp_len_ == pLen)
        {
            random[0] &= 0x7F;
        }

        import(out xa, random);

        for (int i = 0; i < random.Length; i++)
        {
            random[i] = 0;
        }

        DebugLog("        size of DH secret exponent (bits): ", xa.bitCount().ToString());

        ya = g.modPow(xa,p);
    }

    /// <summary>
    /// Create a new key exchanger based on standard parameters
    /// </summary>
    public static BCDiffieHellman? CreateForGroup(DhId group)
    {
        var parameters = DiffieHellmanParameters.GetParametersForGroup(group);
        if (parameters is null)
        {
            return null;
        }

        return new BCDiffieHellman(group, (int)parameters.ExponentLength, parameters.Generator, parameters.Prime);
    }
}
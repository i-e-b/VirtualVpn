using System.Runtime.InteropServices;
using MathGmp.Native;
using static MathGmp.Native.gmp_lib;
// ReSharper disable InconsistentNaming

namespace RawSocketTest.gmpDh;

// src/libstrongswan/crypto/key_exchange.h:156
public struct diffie_hellman_params_t {

	/**
	 * The prime of the group
	 */
	public byte[] prime = Array.Empty<byte>();

	/**
	 * Generator of the group
	 */
	public byte[] generator = Array.Empty<byte>();;

	/**
	 * Exponent length to use
	 */
	public size_t exp_len = (size_t)0;

	/**
	 * Prime order subgroup; for MODP Groups 22-24
	 */
	public byte[] subgroup = Array.Empty<byte>();

	public diffie_hellman_params_t()
	{
	}
}


public class GmpDiffieHellman
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


//typedef struct private_gmp_diffie_hellman_t private_gmp_diffie_hellman_t;


	/**
	 * Diffie Hellman group number.
	 */
	DhId group;

	/*
	 * Generator value.
	 */
	mpz_t g;

	/**
	 * My private value.
	 */
	mpz_t xa;

	/**
	 * My public value.
	 */
	mpz_t ya;

	/**
	 * Other public value.
	 */
	mpz_t yb;

	/**
	 * Shared secret.
	 */
	mpz_t zz;

	/**
	 * Modulus.
	 */
	mpz_t p;

	/**
	 * Modulus length.
	 */
	size_t p_len;

	/**
	 * True if shared secret is computed and stored in my_public_value.
	 */
	bool computed;

//METHOD(key_exchange_t, set_public_key, bool, private_gmp_diffie_hellman_t *this, chunk_t value)
public bool set_public_key(byte[] value)
{
	mpz_t p_min_1 = new mpz_t();

	if (!key_exchange_verify_pubkey(this.group, value)) // check the length is valid
	{
		return false;
	}

	mpz_init(p_min_1);
	mpz_sub_ui(p_min_1, this.p, 1);

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
	if (mpz_cmp_ui(yb, 1) <= 0 ||
		mpz_cmp(yb, p_min_1) >= 0)
	{
		Log("public DH value verification failed: ", "y <= 1 || y >= p - 1");
		mpz_clear(p_min_1);
		return false;
	}
	mpz_clear(p_min_1);
	return true;
}

private void Log(params string[] msgs)
{
	foreach (var msg in msgs)
	{
		Console.Write(msg); Console.Write(" ");
	}
	Console.WriteLine();
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
		case DhId.DH_19:
		case DhId.DH_20:
		case DhId.DH_21:
		case DhId.DH_22:
		case DhId.DH_23:
		case DhId.DH_24:
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

//METHOD(key_exchange_t, get_public_key, bool, private_gmp_diffie_hellman_t *this,chunk_t *value)
public bool get_public_key(out byte[] result)
{
	result = export(ya);
	return true;
	/*value->len = this->p_len;
	value->ptr = mpz_export(NULL, NULL, 1, value->len, 1, 0, this->ya);
	if (value->ptr == NULL)
	{
		value->len = 0;
	}
	return TRUE;*/
}

private static byte[] export(mpz_t src)
{
	var expectedSize = mpz_sizeinbase(src, 2);
	var allocSize = (size_t)((long)expectedSize * 2);
	
	var data = allocate(allocSize);
	size_t size = (size_t)0;
	size_t oneByte = (size_t)1;
	mpz_export(data, ref size, 1, oneByte, 1, 0, src);
	
	var realSize = (int)size;
	var result = new byte[realSize];
	Marshal.Copy(data.ToIntPtr(), result, 0, realSize);
	free(data);
	return result;
}

//METHOD(key_exchange_t, set_private_key, bool, private_gmp_diffie_hellman_t *this, chunk_t value)
public bool set_private_key(byte[] value)
{
	//mpz_import(xa, value.len, 1, 1, 1, 0, value.ptr);
	import(ref xa, value);
	mpz_powm(ya, g, xa, p);
	computed = false;
	return true;
}

private static void import(ref mpz_t target, byte[] value)
{
	var data = allocate((size_t)value.Length);
	Marshal.Copy(value, 0, data.ToIntPtr(), value.Length);
	mpz_import(target, (size_t)value.Length, 1, 1, 1, 0, data);
	free(data);
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

		var one = new mpz_t();
		var q = new mpz_t();
		var p_min_1 = new mpz_t();
		mpz_init(q);
		mpz_init(one);

		diffie_hellman_params_t dh_params = diffie_hellman_get_params(group);
		if (dh_params.subgroup.Length <= 0)
		{
			mpz_init(p_min_1);
			mpz_sub_ui(p_min_1, p, 1);
			mpz_fdiv_q_2exp(q, p_min_1, 1);
			mpz_clear(p_min_1);
		}
		else
		{
			import(ref q, dh_params.subgroup);
			//mpz_import(q, params->subgroup.len, 1, 1, 1, 0, params->subgroup.ptr);
		}
		mpz_powm(one, yb, q, p);
		mpz_clear(q);
		if (mpz_cmp_ui(one, 1) != 0)
		{
			Log("public DH value verification failed: ", "y ^ q mod p != 1");
			mpz_clear(one);
			return true;
		}
		mpz_clear(one);

		mpz_powm(zz, yb, xa, p);
		computed = true;
	}
	
	secret = export(zz);
	return true;
}

METHOD(key_exchange_t, get_method, key_exchange_method_t,
	private_gmp_diffie_hellman_t *this)
{
	return this->group;
}

METHOD(key_exchange_t, destroy, void,
	private_gmp_diffie_hellman_t *this)
{
	mpz_clear(this->p);
	mpz_clear(this->xa);
	mpz_clear(this->ya);
	mpz_clear(this->yb);
	mpz_clear(this->zz);
	mpz_clear(this->g);
	free(this);
}

/**
 * Generic internal constructor
 */
static gmp_diffie_hellman_t *create_generic(key_exchange_method_t group,
											size_t exp_len, chunk_t g, chunk_t p)
{
	private_gmp_diffie_hellman_t *this;
	chunk_t random;
	rng_t *rng;

	INIT(this,
		.public = {
			.ke = {
				.get_shared_secret = _get_shared_secret,
				.set_public_key = _set_public_key,
				.get_public_key = _get_public_key,
				.set_private_key = _set_private_key,
				.get_method = _get_method,
				.destroy = _destroy,
			},
		},
		.group = group,
		.p_len = p.len,
	);

	mpz_init(this->p);
	mpz_init(this->yb);
	mpz_init(this->ya);
	mpz_init(this->xa);
	mpz_init(this->zz);
	mpz_init(this->g);
	mpz_import(this->g, g.len, 1, 1, 1, 0, g.ptr);
	mpz_import(this->p, p.len, 1, 1, 1, 0, p.ptr);

	rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
	if (!rng)
	{
		DBG1(DBG_LIB, "no RNG found for quality %N", rng_quality_names,
			 RNG_STRONG);
		destroy(this);
		return NULL;
	}
	if (!rng->allocate_bytes(rng, exp_len, &random))
	{
		DBG1(DBG_LIB, "failed to allocate DH secret");
		rng->destroy(rng);
		destroy(this);
		return NULL;
	}
	rng->destroy(rng);

	if (exp_len == this->p_len)
	{
		/* achieve bitsof(p)-1 by setting MSB to 0 */
		*random.ptr &= 0x7F;
	}
	mpz_import(this->xa, random.len, 1, 1, 1, 0, random.ptr);
	chunk_clear(&random);
	DBG2(DBG_LIB, "size of DH secret exponent: %u bits",
		 mpz_sizeinbase(this->xa, 2));

	mpz_powm(this->ya, this->g, this->xa, this->p);

	return &this->public;
}

/*
 * Described in header
 */
gmp_diffie_hellman_t *gmp_diffie_hellman_create(key_exchange_method_t group)
{
	diffie_hellman_params_t *params;

	params = diffie_hellman_get_params(group);
	if (!params)
	{
		return NULL;
	}
	return create_generic(group, params->exp_len,
						  params->generator, params->prime);
}

/*
 * Described in header
 */
gmp_diffie_hellman_t *gmp_diffie_hellman_create_custom(
											key_exchange_method_t group, ...)
{
	if (group == MODP_CUSTOM)
	{
		chunk_t g, p;

		VA_ARGS_GET(group, g, p);
		return create_generic(MODP_CUSTOM, p.len, g, p);
	}
	return NULL;
}

}
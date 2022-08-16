using System.Collections;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;

namespace RawSocketTest.Crypto;

// From https://bouncycastle.org/csharp/archive/BigInteger.cs

[SuppressMessage("ReSharper", "UnusedMember.Global")]
[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class BigInt
{
    private int _sign; // -1 means -ve; +1 means +ve; 0 means 0;
    private int[] _magnitude; // array of ints with [0] being the most significant
    private int _nBits = -1; // cache bitCount() value
    private int _nBitLength = -1; // cache bitLength() value
    private const long IntMask = 0xffffffffL;
    private long _mQuote = -1L; // -m^(-1) mod b, b = 2^32 (see Montgomery mult.)


    public static implicit operator BigInt(int v) => valueOf(v);
    public static implicit operator BigInt(long v) => valueOf(v);

    private BigInt()
    {
        _sign = 0;
        _magnitude = Array.Empty<int>();
    }

    private BigInt(int sigNum, int[] mag)
    {
        _sign = sigNum;
        if (mag.Length > 0)
        {
            var i = 0;
            while (i < mag.Length && mag[i] == 0)
            {
                i++;
            }

            if (i == 0)
            {
                _magnitude = mag;
            }
            else
            {
                // strip leading 0 bytes
                var newMag = new int[mag.Length - i];
                Array.Copy(mag, i, newMag, 0, newMag.Length);
                _magnitude = newMag;
                if (newMag.Length == 0)
                    _sign = 0;
            }
        }
        else
        {
            _magnitude = mag;
            _sign = 0;
        }
    }

    public BigInt(string sval, int rdx = 10) //throws FormatException
    {
        if (sval.Length == 0)
        {
            throw new FormatException("Zero length BigInteger");
        }

        NumberStyles style;
        switch (rdx)
        {
            case 10:
                style = NumberStyles.Integer;
                break;
            case 16:
                style = NumberStyles.AllowHexSpecifier;
                break;
            default:
                throw new FormatException("Only base 10 or 16 allowed");
        }


        var index = 0;
        _sign = 1;

        if (sval[0] == '-')
        {
            if (sval.Length == 1)
            {
                throw new FormatException("Zero length BigInteger");
            }

            _sign = -1;
            index = 1;
        }

        // strip leading zeros from the string value
        while (index < sval.Length && int.Parse(sval[index].ToString(), style) == 0)
        {
            index++;
        }

        if (index >= sval.Length)
        {
            // zero value - we're done
            _sign = 0;
            _magnitude = new int[0];
            return;
        }

        //////
        // could we work out the max number of ints required to store
        // sval.length digits in the given base, then allocate that
        // storage in one hit?, then generate the magnitude in one hit too?
        //////

        var b = ZERO;
        var r = valueOf(rdx);
        while (index < sval.Length)
        {
            // (optimise this by taking chunks of digits instead?)
            b = b.multiply(r).add(valueOf(int.Parse(sval[index].ToString(), style)));
            index++;
        }

        _magnitude = b._magnitude;
    }

    public BigInt(byte[] byteVal) //throws FormatException
    {
        if (byteVal.Length == 0)
        {
            throw new FormatException("Zero length BigInteger");
        }

        _sign = 1;
        
        // strip leading zero bytes and return magnitude bytes
        _magnitude = makeMagnitude(byteVal);
    }

    private static int[] makeMagnitude(byte[] bval)
    {
        int i;
        int[] mag;
        int firstSignificant;

        // strip leading zeros
        for (firstSignificant = 0;
             firstSignificant < bval.Length
             && bval[firstSignificant] == 0;
             firstSignificant++)
        {
            // nothing
        }

        if (firstSignificant >= bval.Length)
        {
            return Array.Empty<int>();
        }

        var nInts = (bval.Length - firstSignificant + 3) / 4;
        var bCount = (bval.Length - firstSignificant) % 4;
        if (bCount == 0)
            bCount = 4;

        mag = new int[nInts];
        var v = 0;
        var magnitudeIndex = 0;
        for (i = firstSignificant; i < bval.Length; i++)
        {
            v <<= 8;
            v |= bval[i] & 0xff;
            bCount--;
            if (bCount <= 0)
            {
                mag[magnitudeIndex] = v;
                magnitudeIndex++;
                bCount = 4;
                v = 0;
            }
        }

        if (magnitudeIndex < mag.Length)
        {
            mag[magnitudeIndex] = v;
        }

        return mag;
    }

    public BigInt(int sign, byte[] mag) //throws FormatException
    {
        if (sign < -1 || sign > 1)
        {
            throw new FormatException("Invalid sign value");
        }

        if (sign == 0)
        {
            _sign = 0;
            _magnitude = new int[0];
            return;
        }

        // copy bytes
        _magnitude = makeMagnitude(mag);
        _sign = sign;
    }

    public BigInt(int numBits) //throws ArgumentException
    {
        if (numBits < 0)
        {
            throw new ArgumentException("numBits must be non-negative");
        }

        var nBytes = (numBits + 7) / 8;

        var b = new byte[nBytes];

        if (nBytes > 0)
        {
            nextRndBytes(b);
            // strip off any excess bits in the MSB
            b[0] &= rndMask[8 * nBytes - numBits];
        }

        _magnitude = makeMagnitude(b);
        _sign = 1;
        _nBits = -1;
        _nBitLength = -1;
    }

    private void nextRndBytes(byte[] bytes) => RandomNumberGenerator.Fill(bytes);

    private static readonly byte[] rndMask = { 255, 127, 63, 31, 15, 7, 3, 1 };

    public BigInt(int bitLength, int certainty) //throws ArithmeticException
    {
        var nBytes = (bitLength + 7) / 8;

        var b = new byte[nBytes];

        do
        {
            if (nBytes > 0)
            {
                nextRndBytes(b);
                // strip off any excess bits in the MSB
                b[0] &= rndMask[8 * nBytes - bitLength];
            }

            _magnitude = makeMagnitude(b);
            _sign = 1;
            _nBits = -1;
            _nBitLength = -1;
            _mQuote = -1L;

            if (certainty > 0 && bitLength > 2)
            {
                _magnitude[_magnitude.Length - 1] |= 1;
            }
        } while (this.bitLength() != bitLength || !isProbablePrime(certainty));
    }

    public BigInt abs()
    {
        return (_sign >= 0) ? this : negate();
    }

    /**
         * return a = a + b - b preserved.
         */
    private int[] add(int[] a, int[] b)
    {
        var tI = a.Length - 1;
        var vI = b.Length - 1;
        long m = 0;

        while (vI >= 0)
        {
            m += (a[tI] & IntMask) + (b[vI--] & IntMask);
            a[tI--] = (int)m;
            m = (long)((ulong)m >> 32);
        }

        while (tI >= 0 && m != 0)
        {
            m += (a[tI] & IntMask);
            a[tI--] = (int)m;
            m = (long)((ulong)m >> 32);
        }

        return a;
    }

    public BigInt add(BigInt val) //throws ArithmeticException
    {
        if (val._sign == 0 || val._magnitude.Length == 0)
            return this;
        if (_sign == 0 || _magnitude.Length == 0)
            return val;

        if (val._sign < 0)
        {
            if (_sign > 0)
                return subtract(val.negate());
        }
        else
        {
            if (_sign < 0)
                return val.subtract(negate());
        }

        // both BigIntegers are either +ve or -ve; set the sign later

        int[] mag,
            op;

        if (_magnitude.Length < val._magnitude.Length)
        {
            mag = new int[val._magnitude.Length + 1];

            Array.Copy(val._magnitude, 0, mag, 1, val._magnitude.Length);
            op = _magnitude;
        }
        else
        {
            mag = new int[_magnitude.Length + 1];

            Array.Copy(_magnitude, 0, mag, 1, _magnitude.Length);
            op = val._magnitude;
        }

        return new BigInt(_sign, add(mag, op));
    }

    public int bitCount()
    {
        if (_nBits == -1)
        {
            _nBits = 0;
            for (var i = 0; i < _magnitude.Length; i++)
            {
                _nBits += bitCounts[_magnitude[i] & 0xff];
                _nBits += bitCounts[(_magnitude[i] >> 8) & 0xff];
                _nBits += bitCounts[(_magnitude[i] >> 16) & 0xff];
                _nBits += bitCounts[(_magnitude[i] >> 24) & 0xff];
            }
        }

        return _nBits;
    }

    private readonly static byte[] bitCounts =
    {
        0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 1,
        2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4,
        4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3,
        4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 2, 3, 3, 4, 3, 4, 4, 5,
        3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 1, 2, 2, 3, 2,
        3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 2, 3,
        3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6,
        7, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6,
        5, 6, 6, 7, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 4, 5, 5, 6, 5, 6, 6, 7, 5,
        6, 6, 7, 6, 7, 7, 8
    };

    private int bitLength(int indx, int[] mag)
    {
        int bitLength;

        if (mag.Length == 0)
        {
            return 0;
        }

        while (indx != mag.Length && mag[indx] == 0)
        {
            indx++;
        }

        if (indx == mag.Length)
        {
            return 0;
        }

        // bit length for everything after the first int
        bitLength = 32 * ((mag.Length - indx) - 1);

        // and determine bitlength of first int
        bitLength += bitLen(mag[indx]);

        if (_sign < 0)
        {
            // Check if magnitude is a power of two
            var pow2 = ((bitCounts[mag[indx] & 0xff])
                        + (bitCounts[(mag[indx] >> 8) & 0xff])
                        + (bitCounts[(mag[indx] >> 16) & 0xff]) + (bitCounts[(mag[indx] >> 24) & 0xff])) == 1;

            for (var i = indx + 1; i < mag.Length && pow2; i++)
            {
                pow2 = (mag[i] == 0);
            }

            bitLength -= (pow2 ? 1 : 0);
        }

        return bitLength;
    }

    public int bitLength()
    {
        if (_nBitLength == -1)
        {
            if (_sign == 0)
            {
                _nBitLength = 0;
            }
            else
            {
                _nBitLength = bitLength(0, _magnitude);
            }
        }

        return _nBitLength;
    }

    //
    // bitLen(val) is the number of bits in val.
    //
    static int bitLen(int w)
    {
        // Binary search - decision tree (5 tests, rarely 6)
        return (w < 1 << 15
            ? (w < 1 << 7
                ? (w < 1 << 3
                    ? (w < 1 << 1
                        ? (w < 1 << 0 ? (w < 0 ? 32 : 0) : 1)
                        : (w < 1 << 2 ? 2 : 3))
                    : (w < 1 << 5
                        ? (w < 1 << 4 ? 4 : 5)
                        : (w < 1 << 6 ? 6 : 7)))
                : (w < 1 << 11
                    ? (w < 1 << 9 ? (w < 1 << 8 ? 8 : 9) : (w < 1 << 10 ? 10 : 11))
                    : (w < 1 << 13 ? (w < 1 << 12 ? 12 : 13) : (w < 1 << 14 ? 14 : 15))))
            : (w < 1 << 23
                ? (w < 1 << 19
                    ? (w < 1 << 17 ? (w < 1 << 16 ? 16 : 17) : (w < 1 << 18 ? 18 : 19))
                    : (w < 1 << 21 ? (w < 1 << 20 ? 20 : 21) : (w < 1 << 22 ? 22 : 23)))
                : (w < 1 << 27
                    ? (w < 1 << 25 ? (w < 1 << 24 ? 24 : 25) : (w < 1 << 26 ? 26 : 27))
                    : (w < 1 << 29 ? (w < 1 << 28 ? 28 : 29) : (w < 1 << 30 ? 30 : 31)))));
    }

    public int compareTo(object o)
    {
        return compareTo((BigInt)o);
    }

    /**
         * unsigned comparison on two arrays - note the arrays may
         * start with leading zeros.
         */
    private int compareTo(int xIndx, int[] x, int yIndx, int[] y)
    {
        while (xIndx != x.Length && x[xIndx] == 0)
        {
            xIndx++;
        }

        while (yIndx != y.Length && y[yIndx] == 0)
        {
            yIndx++;
        }

        if ((x.Length - xIndx) < (y.Length - yIndx))
        {
            return -1;
        }

        if ((x.Length - xIndx) > (y.Length - yIndx))
        {
            return 1;
        }

        // lengths of magnitudes the same, test the magnitude values

        while (xIndx < x.Length)
        {
            var v1 = x[xIndx++] & IntMask;
            var v2 = y[yIndx++] & IntMask;
            if (v1 < v2)
            {
                return -1;
            }

            if (v1 > v2)
            {
                return 1;
            }
        }

        return 0;
    }

    public int compareTo(BigInt val)
    {
        if (_sign < val._sign)
            return -1;
        if (_sign > val._sign)
            return 1;

        return compareTo(0, _magnitude, 0, val._magnitude);
    }

    /**
         * return z = x / y - done in place (z value preserved, x contains the
         * remainder)
         */
    private int[] divide(int[] x, int[] y)
    {
        var xyCmp = compareTo(0, x, 0, y);
        int[] count;

        if (xyCmp > 0)
        {
            int[] c;

            var shift = bitLength(0, x) - bitLength(0, y);

            if (shift > 1)
            {
                c = shiftLeft(y, shift - 1);
                count = shiftLeft(ONE._magnitude, shift - 1);
                if (shift % 32 == 0)
                {
                    // Special case where the shift is the size of an int.
                    var countSpecial = new int[shift / 32 + 1];
                    Array.Copy(count, 0, countSpecial, 1, countSpecial.Length - 1);
                    countSpecial[0] = 0;
                    count = countSpecial;
                }
            }
            else
            {
                c = new int[x.Length];
                count = new int[1];

                Array.Copy(y, 0, c, c.Length - y.Length, y.Length);
                count[0] = 1;
            }

            var iCount = new int[count.Length];

            subtract(0, x, 0, c);
            Array.Copy(count, 0, iCount, 0, count.Length);

            var xStart = 0;
            var cStart = 0;
            var iCountStart = 0;

            for (;;)
            {
                var cmp = compareTo(xStart, x, cStart, c);

                while (cmp >= 0)
                {
                    subtract(xStart, x, cStart, c);
                    add(count, iCount);
                    cmp = compareTo(xStart, x, cStart, c);
                }

                xyCmp = compareTo(xStart, x, 0, y);

                if (xyCmp > 0)
                {
                    if (x[xStart] == 0)
                    {
                        xStart++;
                    }

                    shift = bitLength(cStart, c) - bitLength(xStart, x);

                    if (shift == 0)
                    {
                        c = shiftRightOne(cStart, c);
                        iCount = shiftRightOne(iCountStart, iCount);
                    }
                    else
                    {
                        c = shiftRight(cStart, c, shift);
                        iCount = shiftRight(iCountStart, iCount, shift);
                    }

                    if (c[cStart] == 0)
                    {
                        cStart++;
                    }

                    if (iCount[iCountStart] == 0)
                    {
                        iCountStart++;
                    }
                }
                else if (xyCmp == 0)
                {
                    add(count, ONE._magnitude);
                    for (var i = xStart; i != x.Length; i++)
                    {
                        x[i] = 0;
                    }

                    break;
                }
                else
                {
                    break;
                }
            }
        }
        else if (xyCmp == 0)
        {
            count = new int[1];

            count[0] = 1;
        }
        else
        {
            count = new int[1];

            count[0] = 0;
        }

        return count;
    }

    public BigInt divide(BigInt val) //throws ArithmeticException
    {
        if (val._sign == 0)
        {
            throw new ArithmeticException("Divide by zero");
        }

        if (_sign == 0)
        {
            return ZERO;
        }

        if (val.compareTo(ONE) == 0)
        {
            return this;
        }

        var mag = new int[_magnitude.Length];
        Array.Copy(_magnitude, 0, mag, 0, mag.Length);

        return new BigInt(_sign * val._sign, divide(mag, val._magnitude));
    }

    public BigInt[] divideAndRemainder(BigInt val) //throws ArithmeticException
    {
        if (val._sign == 0)
        {
            throw new ArithmeticException("Divide by zero");
        }

        var biggies = new BigInt[2];

        if (_sign == 0)
        {
            biggies[0] = biggies[1] = ZERO;

            return biggies;
        }

        if (val.compareTo(ONE) == 0)
        {
            biggies[0] = this;
            biggies[1] = ZERO;

            return biggies;
        }

        var remainder = new int[_magnitude.Length];
        Array.Copy(_magnitude, 0, remainder, 0, remainder.Length);

        var quotient = divide(remainder, val._magnitude);

        biggies[0] = new BigInt(_sign * val._sign, quotient);
        biggies[1] = new BigInt(_sign, remainder);

        return biggies;
    }

    public override bool Equals(object? val)
    {
        if (val == this)
            return true;

        if (val is not BigInt biggie)
            return false;

        if (biggie._sign != _sign || biggie._magnitude.Length != _magnitude.Length)
            return false;

        for (var i = 0; i < _magnitude.Length; i++)
        {
            if (biggie._magnitude[i] != _magnitude[i])
                return false;
        }

        return true;
    }

    public BigInt gcd(BigInt val)
    {
        if (val._sign == 0)
            return abs();
        if (_sign == 0)
            return val.abs();

        BigInt r;
        var u = this;
        var v = val;

        while (v._sign != 0)
        {
            r = u.mod(v);
            u = v;
            v = r;
        }

        return u;
    }

    public override int GetHashCode()
    {
        return 0;
    }

    public int intValue()
    {
        if (_magnitude.Length == 0)
        {
            return 0;
        }

        if (_sign < 0)
        {
            return -_magnitude[_magnitude.Length - 1];
        }

        return _magnitude[_magnitude.Length - 1];
    }

    /**
         * return whether or not a BigInteger is probably prime with a
         * probability of 1 - (1/2)**certainty.
         * 
         * From Knuth Vol 2, pg 395.
         */
    public bool isProbablePrime(int certainty)
    {
        if (certainty == 0)
        {
            return true;
        }

        var n = abs();

        if (n.Equals(TWO))
        {
            return true;
        }

        if (n.Equals(ONE) || !n.testBit(0))
        {
            return false;
        }

        if ((certainty & 0x1) == 1)
        {
            certainty = certainty / 2 + 1;
        }
        else
        {
            certainty /= 2;
        }

        //
        // let n = 1 + 2^kq
        //
        var q = n.subtract(ONE);
        var k = q.getLowestSetBit();

        q = q.shiftRight(k);

        for (var i = 0; i <= certainty; i++)
        {
            BigInt x;

            do
            {
                x = new BigInt(n.bitLength());
            } while (x.compareTo(ONE) <= 0 || x.compareTo(n) >= 0);

            var j = 0;
            var y = x.modPow(q, n);

            while (!((j == 0 && y.Equals(ONE)) || y.Equals(n.subtract(ONE))))
            {
                if (j > 0 && y.Equals(ONE))
                {
                    return false;
                }

                if (++j == k)
                {
                    return false;
                }

                y = y.modPow(TWO, n);
            }
        }

        return true;
    }

    public long longValue()
    {
        long val;

        if (_magnitude.Length == 0)
        {
            return 0;
        }

        if (_magnitude.Length > 1)
        {
            val = ((long)_magnitude[^2] << 32)
                  | (_magnitude[^1] & IntMask);
        }
        else
        {
            val = (_magnitude[^1] & IntMask);
        }

        if (_sign < 0)
        {
            return -val;
        }

        return val;
    }

    public BigInt max(BigInt val)
    {
        return (compareTo(val) > 0) ? this : val;
    }

    public BigInt min(BigInt val)
    {
        return (compareTo(val) < 0) ? this : val;
    }

    public BigInt mod(BigInt m) //throws ArithmeticException
    {
        if (m._sign <= 0)
        {
            throw new ArithmeticException("BigInteger: modulus is not positive");
        }

        var biggie = remainder(m);

        return (biggie._sign >= 0 ? biggie : biggie.add(m));
    }

    public BigInt modInverse(BigInt m) //throws ArithmeticException
    {
        if (m._sign != 1)
        {
            throw new ArithmeticException("Modulus must be positive");
        }

        var x = new BigInt();
        var y = new BigInt();

        var gcd = extEuclid(this, m, x, y);

        if (!gcd.Equals(ONE))
        {
            throw new ArithmeticException("Numbers not relatively prime.");
        }

        if (x.compareTo(ZERO) < 0)
        {
            x = x.add(m);
        }

        return x;
    }

    /**
         * Calculate the numbers u1, u2, and u3 such that:
         *
         * u1 * a + u2 * b = u3
         *
         * where u3 is the greatest common divider of a and b.
         * a and b using the extended Euclid algorithm (refer p. 323
         * of The Art of Computer Programming vol 2, 2nd ed).
         * This also seems to have the side effect of calculating
         * some form of multiplicative inverse.
         *
         * @param a    First number to calculate gcd for
         * @param b    Second number to calculate gcd for
         * @param u1Out      the return object for the u1 value
         * @param u2Out      the return object for the u2 value
         * @return     The greatest common divisor of a and b
         */
    private static BigInt extEuclid(BigInt a, BigInt b, BigInt u1Out,
        BigInt u2Out)
    {
        BigInt res;

        var u1 = ONE;
        var u3 = a;
        var v1 = ZERO;
        var v3 = b;

        while (v3.compareTo(ZERO) > 0)
        {
            BigInt q,
                tn;
            //tv;

            q = u3.divide(v3);

            tn = u1.subtract(v1.multiply(q));
            u1 = v1;
            v1 = tn;

            tn = u3.subtract(v3.multiply(q));
            u3 = v3;
            v3 = tn;
        }

        u1Out._sign = u1._sign;
        u1Out._magnitude = u1._magnitude;

        res = u3.subtract(u1.multiply(a)).divide(b);
        u2Out._sign = res._sign;
        u2Out._magnitude = res._magnitude;

        return u3;
    }

    /**
         * zero out the array x
         */
    private void zero(int[] x)
    {
        for (var i = 0; i != x.Length; i++)
        {
            x[i] = 0;
        }
    }

    public BigInt modPow(
            BigInt exponent,
            BigInt m)
        //throws ArithmeticException
    {
        int[]? zVal = null;
        int[]? yAccum = null;

        // Montgomery exponentiation is only possible if the modulus is odd,
        // but AFAIK, this is always the case for crypto algo's
        var useMonty = ((m._magnitude[m._magnitude.Length - 1] & 1) == 1);
        long mQ = 0;
        if (useMonty)
        {
            mQ = m.getMQuote();

            // tmp = this * R mod m
            var tmp = shiftLeft(32 * m._magnitude.Length).mod(m);
            zVal = tmp._magnitude;

            useMonty = (zVal.Length == m._magnitude.Length);

            if (useMonty)
            {
                yAccum = new int[m._magnitude.Length + 1];
            }
        }

        if (!useMonty)
        {
            if (_magnitude.Length <= m._magnitude.Length)
            {
                //zAccum = new int[m.magnitude.Length * 2];
                zVal = new int[m._magnitude.Length];

                Array.Copy(_magnitude, 0, zVal, zVal.Length - _magnitude.Length,
                    _magnitude.Length);
            }
            else
            {
                //
                // in normal practice we'll never see this...
                //
                var tmp = remainder(m);

                //zAccum = new int[m.magnitude.Length * 2];
                zVal = new int[m._magnitude.Length];

                Array.Copy(tmp._magnitude, 0, zVal, zVal.Length - tmp._magnitude.Length,
                    tmp._magnitude.Length);
            }

            yAccum = new int[m._magnitude.Length * 2];
        }

        var yVal = new int[m._magnitude.Length];
        if (zVal is null) throw new Exception("Failed to initialise zVal (code error)");
        if (yAccum is null) throw new Exception("Failed to initialise yAccum (code error)");

        //
        // from LSW to MSW
        //
        for (var i = 0; i < exponent._magnitude.Length; i++)
        {
            var v = exponent._magnitude[i];
            var bits = 0;

            if (i == 0)
            {
                while (v > 0)
                {
                    v <<= 1;
                    bits++;
                }

                //
                // first time in initialise y
                //
                Array.Copy(zVal, 0, yVal, 0, zVal.Length);

                v <<= 1;
                bits++;
            }

            while (v != 0)
            {
                if (useMonty)
                {
                    // Montgomery square algo doesn't exist, and a normal
                    // square followed by a Montgomery reduction proved to
                    // be almost as heavy as a Montgomery multiply.
                    multiplyMonty(yAccum, yVal, yVal, m._magnitude, mQ);
                }
                else
                {
                    square(yAccum, yVal);
                    remainder(yAccum, m._magnitude);
                    Array.Copy(yAccum, yAccum.Length - yVal.Length, yVal, 0, yVal.Length);
                    zero(yAccum);
                }

                bits++;

                if (v < 0)
                {
                    if (useMonty)
                    {
                        multiplyMonty(yAccum, yVal, zVal, m._magnitude, mQ);
                    }
                    else
                    {
                        multiply(yAccum, yVal, zVal);
                        remainder(yAccum, m._magnitude);
                        Array.Copy(yAccum, yAccum.Length - yVal.Length, yVal, 0,
                            yVal.Length);
                        zero(yAccum);
                    }
                }

                v <<= 1;
            }

            while (bits < 32)
            {
                if (useMonty)
                {
                    multiplyMonty(yAccum, yVal, yVal, m._magnitude, mQ);
                }
                else
                {
                    square(yAccum, yVal);
                    remainder(yAccum, m._magnitude);
                    Array.Copy(yAccum, yAccum.Length - yVal.Length, yVal, 0, yVal.Length);
                    zero(yAccum);
                }

                bits++;
            }
        }

        if (useMonty)
        {
            // Return y * R^(-1) mod m by doing y * 1 * R^(-1) mod m
            zero(zVal);
            zVal[zVal.Length - 1] = 1;
            multiplyMonty(yAccum, yVal, zVal, m._magnitude, mQ);
        }

        return new BigInt(1, yVal);
    }

    /**
         * return w with w = x * x - w is assumed to have enough space.
         */
    private void square(int[] w, int[] x)
    {
        long u1,
            u2,
            c;

        if (w.Length != 2 * x.Length)
        {
            throw new ArgumentException("no I don't think so...");
        }

        for (var i = x.Length - 1; i != 0; i--)
        {
            var v = (x[i] & IntMask);

            u1 = v * v;
            u2 = (long)((ulong)u1 >> 32);
            u1 &= IntMask;

            u1 += (w[2 * i + 1] & IntMask);

            w[2 * i + 1] = (int)u1;
            c = u2 + (u1 >> 32);

            for (var j = i - 1; j >= 0; j--)
            {
                u1 = (x[j] & IntMask) * v;
                u2 = (long)((ulong)u1 >> 31); // multiply by 2!
                u1 = (u1 & 0x7fffffff) << 1; // multiply by 2!
                u1 += (w[i + j + 1] & IntMask) + c;

                w[i + j + 1] = (int)u1;
                c = u2 + (long)((ulong)u1 >> 32);
            }

            c += w[i] & IntMask;
            w[i] = (int)c;
            w[i - 1] = (int)(c >> 32);
        }

        u1 = (x[0] & IntMask);
        u1 *= u1;
        u2 = (long)((ulong)u1 >> 32);
        u1 &= IntMask;

        u1 += (w[1] & IntMask);

        w[1] = (int)u1;
        w[0] = (int)(u2 + (u1 >> 32) + w[0]);
    }

    /**
         * return x with x = y * z - x is assumed to have enough space.
         */
    private int[] multiply(int[] x, int[] y, int[] z)
    {
        for (var i = z.Length - 1; i >= 0; i--)
        {
            var a = z[i] & IntMask;
            long value = 0;

            for (var j = y.Length - 1; j >= 0; j--)
            {
                value += a * (y[j] & IntMask) + (x[i + j + 1] & IntMask);

                x[i + j + 1] = (int)value;

                value = (long)((ulong)value >> 32);
            }

            x[i] = (int)value;
        }

        return x;
    }

    /**
         * Calculate mQuote = -m^(-1) mod b with b = 2^32 (32 = word size)
         */
    private long getMQuote()
    {
        if (_mQuote != -1L)
        {
            // allready calculated
            return _mQuote;
        }

        if ((_magnitude[_magnitude.Length - 1] & 1) == 0)
        {
            return -1L; // not for even numbers
        }

        byte[] bytes = { 1, 0, 0, 0, 0 };
        var b = new BigInt(1, bytes); // 2^32
        _mQuote = negate().mod(b).modInverse(b).longValue();
        return _mQuote;
    }

    /**
         * Montgomery multiplication: a = x * y * R^(-1) mod m
         *
         * Based algorithm 14.36 of Handbook of Applied Cryptography.
         *
         * <li> m, x, y should have length n </li>
         * <li> a should have length (n + 1) </li>
         * <li> b = 2^32, R = b^n </li>
         *
         * The result is put in x
         *
         * NOTE: the indices of x, y, m, a different in HAC and in Java
         */
    public void multiplyMonty(int[] a, int[] x, int[] y, int[] m, long mQuote)
        // mQuote = -m^(-1) mod b
    {
        var n = m.Length;
        var nMinus1 = n - 1;
        var y_0 = y[n - 1] & IntMask;

        // 1. a = 0 (Notation: a = (a_{n} a_{n-1} ... a_{0})_{b} )
        for (var i = 0; i <= n; i++)
        {
            a[i] = 0;
        }

        // 2. for i from 0 to (n - 1) do the following:
        for (var i = n; i > 0; i--)
        {
            var x_i = x[i - 1] & IntMask;

            // 2.1 u = ((a[0] + (x[i] * y[0]) * mQuote) mod b
            var u = ((((a[n] & IntMask) + ((x_i * y_0) & IntMask)) & IntMask) * mQuote) & IntMask;

            // 2.2 a = (a + x_i * y + u * m) / b
            var prod1 = x_i * y_0;
            var prod2 = u * (m[n - 1] & IntMask);
            var tmp = (a[n] & IntMask) + (prod1 & IntMask) + (prod2 & IntMask);
            var carry = (long)((ulong)prod1 >> 32) + (long)((ulong)prod2 >> 32) + (long)((ulong)tmp >> 32);
            for (var j = nMinus1; j > 0; j--)
            {
                prod1 = x_i * (y[j - 1] & IntMask);
                prod2 = u * (m[j - 1] & IntMask);
                tmp = (a[j] & IntMask) + (prod1 & IntMask) + (prod2 & IntMask) + (carry & IntMask);
                carry = (long)((ulong)carry >> 32) + (long)((ulong)prod1 >> 32) +
                        (long)((ulong)prod2 >> 32) + (long)((ulong)tmp >> 32);
                a[j + 1] = (int)tmp; // division by b
            }

            carry += (a[0] & IntMask);
            a[1] = (int)carry;
            a[0] = (int)((ulong)carry >> 32); // OJO!!!!!
        }

        // 3. if x >= m the x = x - m
        if (compareTo(0, a, 0, m) >= 0)
        {
            subtract(0, a, 0, m);
        }

        // put the result in x
        for (var i = 0; i < n; i++)
        {
            x[i] = a[i + 1];
        }
    }

    public BigInt multiply(BigInt val)
    {
        if (_sign == 0 || val._sign == 0)
            return ZERO;

        var res = new int[_magnitude.Length + val._magnitude.Length];

        return new BigInt(_sign * val._sign, multiply(res, _magnitude, val._magnitude));
    }

    public BigInt negate()
    {
        return new BigInt(-_sign, _magnitude);
    }

    public BigInt pow(int exp) //throws ArithmeticException
    {
        if (exp < 0)
            throw new ArithmeticException("Negative exponent");
        if (_sign == 0)
            return (exp == 0 ? ONE : this);

        BigInt y,
            z;
        y = ONE;
        z = this;

        while (exp != 0)
        {
            if ((exp & 0x1) == 1)
            {
                y = y.multiply(z);
            }

            exp >>= 1;
            if (exp != 0)
            {
                z = z.multiply(z);
            }
        }

        return y;
    }

    /**
         * return x = x % y - done in place (y value preserved)
         */
    private int[] remainder(int[] x, int[] y)
    {
        var xyCmp = compareTo(0, x, 0, y);

        if (xyCmp > 0)
        {
            int[] c;
            var shift = bitLength(0, x) - bitLength(0, y);

            if (shift > 1)
            {
                c = shiftLeft(y, shift - 1);
            }
            else
            {
                c = new int[x.Length];

                Array.Copy(y, 0, c, c.Length - y.Length, y.Length);
            }

            subtract(0, x, 0, c);

            var xStart = 0;
            var cStart = 0;

            for (;;)
            {
                var cmp = compareTo(xStart, x, cStart, c);

                while (cmp >= 0)
                {
                    subtract(xStart, x, cStart, c);
                    cmp = compareTo(xStart, x, cStart, c);
                }

                xyCmp = compareTo(xStart, x, 0, y);

                if (xyCmp > 0)
                {
                    if (x[xStart] == 0)
                    {
                        xStart++;
                    }

                    shift = bitLength(cStart, c) - bitLength(xStart, x);

                    if (shift == 0)
                    {
                        c = shiftRightOne(cStart, c);
                    }
                    else
                    {
                        c = shiftRight(cStart, c, shift);
                    }

                    if (c[cStart] == 0)
                    {
                        cStart++;
                    }
                }
                else if (xyCmp == 0)
                {
                    for (var i = xStart; i != x.Length; i++)
                    {
                        x[i] = 0;
                    }

                    break;
                }
                else
                {
                    break;
                }
            }
        }
        else if (xyCmp == 0)
        {
            for (var i = 0; i != x.Length; i++)
            {
                x[i] = 0;
            }
        }

        return x;
    }

    public BigInt remainder(BigInt val) //throws ArithmeticException
    {
        if (val._sign == 0)
        {
            throw new ArithmeticException("BigInteger: Divide by zero");
        }

        if (_sign == 0)
        {
            return ZERO;
        }

        var res = new int[_magnitude.Length];

        Array.Copy(_magnitude, 0, res, 0, res.Length);

        return new BigInt(_sign, remainder(res, val._magnitude));
    }

    /**
         * do a left shift - this returns a new array.
         */
    private int[] shiftLeft(int[] mag, int n)
    {
        var nInts = (int)((uint)n >> 5);
        var nBits = n & 0x1f;
        var magLen = mag.Length;
        int[] newMag;

        if (nBits == 0)
        {
            newMag = new int[magLen + nInts];
            for (var i = 0; i < magLen; i++)
            {
                newMag[i] = mag[i];
            }
        }
        else
        {
            var i = 0;
            var nBits2 = 32 - nBits;
            var highBits = (int)((uint)mag[0] >> nBits2);

            if (highBits != 0)
            {
                newMag = new int[magLen + nInts + 1];
                newMag[i++] = highBits;
            }
            else
            {
                newMag = new int[magLen + nInts];
            }

            var m = mag[0];
            for (var j = 0; j < magLen - 1; j++)
            {
                var next = mag[j + 1];

                newMag[i++] = (m << nBits) | (int)((uint)next >> nBits2);
                m = next;
            }

            newMag[i] = mag[magLen - 1] << nBits;
        }

        return newMag;
    }

    public BigInt shiftLeft(int n)
    {
        if (_sign == 0 || _magnitude.Length == 0)
        {
            return ZERO;
        }

        if (n == 0)
        {
            return this;
        }

        if (n < 0)
        {
            return shiftRight(-n);
        }

        return new BigInt(_sign, shiftLeft(_magnitude, n));
    }

    /**
         * do a right shift - this does it in place.
         */
    private int[] shiftRight(int start, int[] mag, int n)
    {
        var nInts = (int)((uint)n >> 5) + start;
        var nBits = n & 0x1f;
        var magLen = mag.Length;

        if (nInts != start)
        {
            var delta = (nInts - start);

            for (var i = magLen - 1; i >= nInts; i--)
            {
                mag[i] = mag[i - delta];
            }

            for (var i = nInts - 1; i >= start; i--)
            {
                mag[i] = 0;
            }
        }

        if (nBits != 0)
        {
            var nBits2 = 32 - nBits;
            var m = mag[magLen - 1];

            for (var i = magLen - 1; i >= nInts + 1; i--)
            {
                var next = mag[i - 1];

                mag[i] = (int)((uint)m >> nBits) | (next << nBits2);
                m = next;
            }

            mag[nInts] = (int)((uint)mag[nInts] >> nBits);
        }

        return mag;
    }

    /**
         * do a right shift by one - this does it in place.
         */
    private int[] shiftRightOne(int start, int[] mag)
    {
        var magLen = mag.Length;

        var m = mag[magLen - 1];

        for (var i = magLen - 1; i >= start + 1; i--)
        {
            var next = mag[i - 1];

            mag[i] = ((int)((uint)m >> 1)) | (next << 31);
            m = next;
        }

        mag[start] = (int)((uint)mag[start] >> 1);

        return mag;
    }

    public BigInt shiftRight(int n)
    {
        if (n == 0)
        {
            return this;
        }

        if (n < 0)
        {
            return shiftLeft(-n);
        }

        if (n >= bitLength())
        {
            return (_sign < 0 ? valueOf(-1) : ZERO);
        }

        var res = new int[_magnitude.Length];

        Array.Copy(_magnitude, 0, res, 0, res.Length);

        return new BigInt(_sign, shiftRight(0, res, n));
    }

    public int signum()
    {
        return _sign;
    }

    /**
         * returns x = x - y - we assume x is >= y
         */
    private int[] subtract(int xStart, int[] x, int yStart, int[] y)
    {
        var iT = x.Length - 1;
        var iV = y.Length - 1;
        long m;
        var borrow = 0;

        do
        {
            m = (x[iT] & IntMask) - (y[iV--] & IntMask) + borrow;

            x[iT--] = (int)m;

            if (m < 0)
            {
                borrow = -1;
            }
            else
            {
                borrow = 0;
            }
        } while (iV >= yStart);

        while (iT >= xStart)
        {
            m = (x[iT] & IntMask) + borrow;
            x[iT--] = (int)m;

            if (m < 0)
            {
                borrow = -1;
            }
            else
            {
                break;
            }
        }

        return x;
    }

    public BigInt subtract(BigInt val)
    {
        if (val._sign == 0 || val._magnitude.Length == 0)
        {
            return this;
        }

        if (_sign == 0 || _magnitude.Length == 0)
        {
            return val.negate();
        }

        if (val._sign < 0)
        {
            if (_sign > 0)
                return add(val.negate());
        }
        else
        {
            if (_sign < 0)
                return add(val.negate());
        }

        BigInt bigun,
            littlun;
        var compare = compareTo(val);
        if (compare == 0)
        {
            return ZERO;
        }

        if (compare < 0)
        {
            bigun = val;
            littlun = this;
        }
        else
        {
            bigun = this;
            littlun = val;
        }

        var res = new int[bigun._magnitude.Length];

        Array.Copy(bigun._magnitude, 0, res, 0, res.Length);

        return new BigInt(_sign * compare, subtract(0, res, 0, littlun._magnitude));
    }

    public byte[] toByteArray()
    {
        var bitLength = this.bitLength();
        var bytes = new byte[bitLength / 8 + 1];

        var bytesCopied = 4;
        var mag = 0;
        var ofs = _magnitude.Length - 1;
        var carry = 1;
        long lMag;
        for (var i = bytes.Length - 1; i >= 0; i--)
        {
            if (bytesCopied == 4 && ofs >= 0)
            {
                if (_sign < 0)
                {
                    // we are dealing with a +ve number and we want a -ve one, so
                    // invert the magnitude ints and add 1 (propagating the carry)
                    // to make a 2's complement -ve number
                    lMag = ~_magnitude[ofs--] & IntMask;
                    lMag += carry;
                    if ((lMag & ~IntMask) != 0)
                        carry = 1;
                    else
                        carry = 0;
                    mag = (int)(lMag & IntMask);
                }
                else
                {
                    mag = _magnitude[ofs--];
                }

                bytesCopied = 1;
            }
            else
            {
                mag = (int)((uint)mag >> 8);
                bytesCopied++;
            }

            bytes[i] = (byte)mag;
        }

        return bytes;
    }

    public override string ToString()
    {
        return ToString(10);
    }

    public string ToString(int rdx)
    {
        string format;
        switch (rdx)
        {
            case 10:
                format = "d";
                break;
            case 16:
                format = "x";
                break;
            default:
                throw new FormatException("Only base 10 or 16 are allowed");
        }

        if (_sign == 0)
        {
            return "0";
        }

        var s = "";
        string h;

        if (rdx == 16)
        {
            for (var i = 0; i < _magnitude.Length; i++)
            {
                h = "0000000" + _magnitude[i].ToString("x");
                h = h.Substring(h.Length - 8);
                s += h;
            }
        }
        else
        {
            // This is algorithm 1a from chapter 4.4 in Seminumerical Algorithms, slow but it works
            var S = new Stack();
            var bs = new BigInt(rdx.ToString());
            // The sign is handled separatly.
            // Notice however that for this to work, radix 16 _MUST_ be a special case,
            // unless we want to enter a recursion well. In their infinite wisdom, why did not 
            // the Sun engineers made a c'tor for BigIntegers taking a BigInteger as parameter?
            // (Answer: Becuase Sun's BigIntger is clonable, something bouncycastle's isn't.)
            var u = new BigInt(abs().ToString(16), 16);
            BigInt b;

            // For speed, maye these test should look directly a u.magnitude.Length?
            while (!u.Equals(ZERO))
            {
                b = u.mod(bs);
                if (b.Equals(ZERO))
                    S.Push("0");
                else
                {
                    // see how to interact with different bases
                    S.Push(b._magnitude[0].ToString(format));
                }

                u = u.divide(bs);
            }

            // Then pop the stack
            while (S.Count != 0)
                s += S.Pop();
        }

        // Strip leading zeros.
        while (s.Length > 1 && s[0] == '0')
            s = s.Substring(1);

        if (s.Length == 0)
            s = "0";
        else if (_sign == -1)
            s = "-" + s;

        return s;
    }

    public static readonly BigInt ZERO = new BigInt(0, new byte[0]);
    public static readonly BigInt ONE = valueOf(1);
    private static readonly BigInt TWO = valueOf(2);

    public static BigInt valueOf(long val)
    {
        if (val == 0)
        {
            return ZERO;
        }

        // store val into a byte array
        var b = new byte[8];
        for (var i = 0; i < 8; i++)
        {
            b[7 - i] = (byte)val;
            val >>= 8;
        }

        return new BigInt(b);
    }

    public int max(int a, int b)
    {
        if (a < b)
            return b;
        return a;
    }

    public int getLowestSetBit()
    {
        if (Equals(ZERO))
        {
            return -1;
        }

        var w = _magnitude.Length - 1;

        while (w >= 0)
        {
            if (_magnitude[w] != 0)
            {
                break;
            }

            w--;
        }

        var b = 31;

        while (b > 0)
        {
            if ((uint)(_magnitude[w] << b) == 0x80000000)
            {
                break;
            }

            b--;
        }

        return (((_magnitude.Length - 1) - w) * 32 + (31 - b));
    }

    public bool testBit(int n) //throws ArithmeticException
    {
        if (n < 0)
        {
            throw new ArithmeticException("Bit position must not be negative");
        }

        if ((n / 32) >= _magnitude.Length)
        {
            return _sign < 0;
        }

        return ((_magnitude[(_magnitude.Length - 1) - n / 32] >> (n % 32)) & 1) > 0;
    }
}
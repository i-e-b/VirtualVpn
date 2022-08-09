namespace RawSocketTest.Crypto;

public class Big
{
    private const long IntMask = 0xffffffffL;

    private int _sign; // -1 means -ve; +1 means +ve; 0 means 0;
    private int[] _magnitude; // array of ints with [0] being the most significant
    private int _nBitLength = -1; // cache bitLength() value

    private Big()
    {
        _magnitude = Array.Empty<int>();
    }

    private Big(int sign, int[] mag)
    {
        _sign = sign;
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

    private Big(byte[] bVal) //throws FormatException
    {
        if (bVal.Length == 0)
        {
            throw new FormatException("Zero length BigInteger");
        }

        _sign = 1;

        // strip leading zero bytes and return magnitude bytes
        _magnitude = MakeMagnitude(bVal);
    }

    private static int[] MakeMagnitude(byte[] bVal)
    {
        int i;
        int firstSignificant;

        // strip leading zeros
        for (firstSignificant = 0;
             firstSignificant < bVal.Length && bVal[firstSignificant] == 0;
             firstSignificant++)
        {
        }

        if (firstSignificant >= bVal.Length)
        {
            return Array.Empty<int>();
        }

        var nInts = (bVal.Length - firstSignificant + 3) / 4;
        var bCount = (bVal.Length - firstSignificant) % 4;
        if (bCount == 0)
            bCount = 4;

        var mag = new int[nInts];
        var v = 0;
        var magnitudeIndex = 0;
        for (i = firstSignificant; i < bVal.Length; i++)
        {
            v <<= 8;
            v |= bVal[i] & 0xff;
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

    public Big(int sign, byte[] mag) //throws FormatException
    {
        switch (sign)
        {
            case < -1:
            case > 1:
                throw new FormatException("Invalid sign value");
            case 0:
                _sign = 0;
                _magnitude = Array.Empty<int>();
                return;

            default:
                // copy bytes
                _magnitude = MakeMagnitude(mag);
                _sign = sign;
                break;
        }
    }

    private Big Abs() => _sign >= 0 ? this : Negate();

    /**
         * return a = a + b - b preserved.
         */
    private static int[] Add(int[] a, int[] b)
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
            m += a[tI] & IntMask;
            a[tI--] = (int)m;
            m = (long)((ulong)m >> 32);
        }

        return a;
    }

    public Big Add(Big val) //throws ArithmeticException
    {
        if (val._sign == 0 || val._magnitude.Length == 0)
            return this;
        if (_sign == 0 || _magnitude.Length == 0)
            return val;

        if (val._sign < 0)
        {
            if (_sign > 0)
                return Subtract(val.Negate());
        }
        else
        {
            if (_sign < 0)
                return val.Subtract(Negate());
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

        return new Big(_sign, Add(mag, op));
    }

    private static readonly byte[] _bitCounts =
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

    private int BitLength(int idx, int[] mag)
    {
        if (mag.Length == 0)
        {
            return 0;
        }

        while (idx != mag.Length && mag[idx] == 0)
        {
            idx++;
        }

        if (idx == mag.Length)
        {
            return 0;
        }

        // bit length for everything after the first int
        var bitLength = 32 * (mag.Length - idx - 1);

        // and determine bitLength of first int
        bitLength += BitLen(mag[idx]);

        if (_sign < 0)
        {
            // Check if magnitude is a power of two
            var pow2 = _bitCounts[mag[idx] & 0xff]
                + _bitCounts[(mag[idx] >> 8) & 0xff]
                + _bitCounts[(mag[idx] >> 16) & 0xff] + _bitCounts[(mag[idx] >> 24) & 0xff] == 1;

            for (var i = idx + 1; i < mag.Length && pow2; i++)
            {
                pow2 = mag[i] == 0;
            }

            bitLength -= pow2 ? 1 : 0;
        }

        return bitLength;
    }

    public int BitLength()
    {
        if (_nBitLength != -1) return _nBitLength;

        _nBitLength = _sign == 0 ? 0 : BitLength(0, _magnitude);

        return _nBitLength;
    }

    //
    // bitLen(val) is the number of bits in val.
    //
    private static int BitLen(int w)
    {
        // Binary search - decision tree (5 tests, rarely 6)
        return w < 1 << 15
            ? w < 1 << 7
                ? w < 1 << 3
                    ? w < 1 << 1
                        ? w < 1 << 0 ? w < 0 ? 32 : 0 : 1
                        : w < 1 << 2
                            ? 2
                            : 3
                    : w < 1 << 5
                        ? w < 1 << 4 ? 4 : 5
                        : w < 1 << 6
                            ? 6
                            : 7
                : w < 1 << 11
                    ? w < 1 << 9 ? w < 1 << 8 ? 8 : 9 : w < 1 << 10 ? 10 : 11
                    : w < 1 << 13
                        ? w < 1 << 12 ? 12 : 13
                        : w < 1 << 14
                            ? 14
                            : 15
            : w < 1 << 23
                ? w < 1 << 19
                    ? w < 1 << 17 ? w < 1 << 16 ? 16 : 17 : w < 1 << 18 ? 18 : 19
                    : w < 1 << 21
                        ? w < 1 << 20 ? 20 : 21
                        : w < 1 << 22
                            ? 22
                            : 23
                : w < 1 << 27
                    ? w < 1 << 25 ? w < 1 << 24 ? 24 : 25 : w < 1 << 26 ? 26 : 27
                    : w < 1 << 29
                        ? w < 1 << 28 ? 28 : 29
                        : w < 1 << 30
                            ? 30
                            : 31;
    }

    /**
         * unsigned comparison on two arrays - note the arrays may
         * start with leading zeros.
         */
    private static int CompareTo(int xIdx, int[] x, int yIdx, int[] y)
    {
        while (xIdx != x.Length && x[xIdx] == 0)
        {
            xIdx++;
        }

        while (yIdx != y.Length && y[yIdx] == 0)
        {
            yIdx++;
        }

        if (x.Length - xIdx < y.Length - yIdx)
        {
            return -1;
        }

        if (x.Length - xIdx > y.Length - yIdx)
        {
            return 1;
        }

        // lengths of magnitudes the same, test the magnitude values

        while (xIdx < x.Length)
        {
            var v1 = x[xIdx++] & IntMask;
            var v2 = y[yIdx++] & IntMask;
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

    public int CompareTo(Big val)
    {
        if (_sign < val._sign)
            return -1;
        if (_sign > val._sign)
            return 1;

        return CompareTo(0, _magnitude, 0, val._magnitude);
    }

    /**
         * return z = x / y - done in place (z value preserved, x contains the
         * remainder)
         */
    private int[] Divide(int[] x, int[] y)
    {
        var xyCmp = CompareTo(0, x, 0, y);
        int[] count;

        if (xyCmp > 0)
        {
            int[] c;

            var shift = BitLength(0, x) - BitLength(0, y);

            if (shift > 1)
            {
                c = ShiftLeft(y, shift - 1);
                count = ShiftLeft(_one._magnitude, shift - 1);
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

            Subtract(0, x, 0, c);
            Array.Copy(count, 0, iCount, 0, count.Length);

            var xStart = 0;
            var cStart = 0;
            var iCountStart = 0;

            for (;;)
            {
                var cmp = CompareTo(xStart, x, cStart, c);

                while (cmp >= 0)
                {
                    Subtract(xStart, x, cStart, c);
                    Add(count, iCount);
                    cmp = CompareTo(xStart, x, cStart, c);
                }

                xyCmp = CompareTo(xStart, x, 0, y);

                if (xyCmp > 0)
                {
                    if (x[xStart] == 0)
                    {
                        xStart++;
                    }

                    shift = BitLength(cStart, c) - BitLength(xStart, x);

                    if (shift == 0)
                    {
                        c = ShiftRightOne(cStart, c);
                        iCount = ShiftRightOne(iCountStart, iCount);
                    }
                    else
                    {
                        c = ShiftRight(cStart, c, shift);
                        iCount = ShiftRight(iCountStart, iCount, shift);
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
                    Add(count, _one._magnitude);
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

    private Big Divide(Big val) //throws ArithmeticException
    {
        if (val._sign == 0)
        {
            throw new ArithmeticException("Divide by zero");
        }

        if (_sign == 0)
        {
            return Zero;
        }

        if (val.CompareTo(_one) == 0)
        {
            return this;
        }

        var mag = new int[_magnitude.Length];
        Array.Copy(_magnitude, 0, mag, 0, mag.Length);

        return new Big(_sign * val._sign, Divide(mag, val._magnitude));
    }

    public override bool Equals(object? val)
    {
        if (val == this)
            return true;

        if (val is not Big bigInteger)
            return false;

        if (bigInteger._sign != _sign || bigInteger._magnitude.Length != _magnitude.Length)
            return false;

        for (var i = 0; i < _magnitude.Length; i++)
        {
            if (bigInteger._magnitude[i] != _magnitude[i]) return false;
        }

        return true;
    }

    public Big Gcd(Big val)
    {
        if (val._sign == 0)
            return Abs();
        if (_sign == 0)
            return val.Abs();

        var u = this;
        var v = val;

        while (v._sign != 0)
        {
            var r = u.Mod(v);
            u = v;
            v = r;
        }

        return u;
    }

    public override int GetHashCode()
    {
        // ReSharper disable once NonReadonlyMemberInGetHashCode
        return _magnitude.GetHashCode();
    }

    public Big Mod(Big m)
    {
        var biggie = Remainder(m);
        return biggie._sign >= 0 ? biggie : biggie.Add(m);
    }

    public Big ModInverse(Big m) //throws ArithmeticException
    {
        var x = new Big();
        var y = new Big();

        var gcd = ExtEuclid(this, m, x, y);

        if (!gcd.Equals(_one))
        {
            throw new ArithmeticException("Numbers not relatively prime.");
        }

        if (x.CompareTo(Zero) < 0)
        {
            x = x.Add(m);
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
    private static Big ExtEuclid(Big a, Big b, Big u1Out,
        Big u2Out)
    {
        var u1 = _one;
        var u3 = a;
        var v1 = Zero;
        var v3 = b;

        while (v3.CompareTo(Zero) > 0)
        {
            var q = u3.Divide(v3);

            var tn = u1.Subtract(v1.Multiply(q));
            u1 = v1;
            v1 = tn;

            tn = u3.Subtract(v3.Multiply(q));
            u3 = v3;
            v3 = tn;
        }

        u1Out._sign = u1._sign;
        u1Out._magnitude = u1._magnitude;

        var res = u3.Subtract(u1.Multiply(a)).Divide(b);
        u2Out._sign = res._sign;
        u2Out._magnitude = res._magnitude;

        return u3;
    }

    /**
         * return x with x = y * z - x is assumed to have enough space.
         */
    private static int[] Multiply(int[] x, int[] y, int[] z)
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

    public Big Multiply(Big val)
    {
        if (_sign == 0 || val._sign == 0)
            return Zero;

        var res = new int[_magnitude.Length + val._magnitude.Length];

        return new Big(_sign * val._sign, Multiply(res, _magnitude, val._magnitude));
    }

    private Big Negate()
    {
        return new Big(-_sign, _magnitude);
    }

    public Big Pow(int exp) //throws ArithmeticException
    {
        if (exp < 0)
            throw new ArithmeticException("Negative exponent");
        if (_sign == 0)
            return exp == 0 ? _one : this;

        var y = _one;
        var z = this;

        while (exp != 0)
        {
            if ((exp & 0x1) == 1)
            {
                y = y.Multiply(z);
            }

            exp >>= 1;
            if (exp != 0)
            {
                z = z.Multiply(z);
            }
        }

        return y;
    }

    /**
         * return x = x % y - done in place (y value preserved)
         */
    private int[] Remainder(int[] x, int[] y)
    {
        var xyCmp = CompareTo(0, x, 0, y);

        if (xyCmp <= 0)
        {
            if (xyCmp != 0) return x;
            for (var i = 0; i != x.Length; i++)
            {
                x[i] = 0;
            }
        }
        else
        {
            int[] c;
            var shift = BitLength(0, x) - BitLength(0, y);

            if (shift > 1)
            {
                c = ShiftLeft(y, shift - 1);
            }
            else
            {
                c = new int[x.Length];

                Array.Copy(y, 0, c, c.Length - y.Length, y.Length);
            }

            Subtract(0, x, 0, c);

            var xStart = 0;
            var cStart = 0;

            for (;;)
            {
                var cmp = CompareTo(xStart, x, cStart, c);

                while (cmp >= 0)
                {
                    Subtract(xStart, x, cStart, c);
                    cmp = CompareTo(xStart, x, cStart, c);
                }

                xyCmp = CompareTo(xStart, x, 0, y);

                if (xyCmp > 0)
                {
                    if (x[xStart] == 0)
                    {
                        xStart++;
                    }

                    shift = BitLength(cStart, c) - BitLength(xStart, x);

                    c = shift == 0 ? ShiftRightOne(cStart, c) : ShiftRight(cStart, c, shift);

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

        return x;
    }

    private Big Remainder(Big val) //throws ArithmeticException
    {
        if (val._sign == 0)
        {
            throw new ArithmeticException("BigInteger: Divide by zero");
        }

        if (_sign == 0)
        {
            return Zero;
        }

        var res = new int[_magnitude.Length];

        Array.Copy(_magnitude, 0, res, 0, res.Length);

        return new Big(_sign, Remainder(res, val._magnitude));
    }

    /**
         * do a left shift - this returns a new array.
         */
    private static int[] ShiftLeft(int[] mag, int n)
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

    private Big ShiftLeft(int n)
    {
        if (_sign == 0 || _magnitude.Length == 0) return Zero;

        if (n == 0) return this;
        if (n < 0) return ShiftRight(-n);

        return new Big(_sign, ShiftLeft(_magnitude, n));
    }

    /**
         * do a right shift - this does it in place.
         */
    private static int[] ShiftRight(int start, int[] mag, int n)
    {
        var nInts = (int)((uint)n >> 5) + start;
        var nBits = n & 0x1f;
        var magLen = mag.Length;

        if (nInts != start)
        {
            var delta = nInts - start;

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
    private static int[] ShiftRightOne(int start, int[] mag)
    {
        var magLen = mag.Length;

        var m = mag[magLen - 1];

        for (var i = magLen - 1; i >= start + 1; i--)
        {
            var next = mag[i - 1];

            mag[i] = (int)((uint)m >> 1) | (next << 31);
            m = next;
        }

        mag[start] = (int)((uint)mag[start] >> 1);

        return mag;
    }

    private Big ShiftRight(int n)
    {
        if (n == 0) return this;

        if (n < 0) return ShiftLeft(-n);

        if (n >= BitLength())
        {
            return _sign < 0 ? ValueOf(-1) : Zero;
        }

        var res = new int[_magnitude.Length];

        Array.Copy(_magnitude, 0, res, 0, res.Length);

        return new Big(_sign, ShiftRight(0, res, n));
    }

    /**
         * returns x = x - y - we assume x is >= y
         */
    private static int[] Subtract(int xStart, int[] x, int yStart, int[] y)
    {
        var iT = x.Length - 1;
        var iV = y.Length - 1;
        long m;
        var borrow = 0;

        do
        {
            m = (x[iT] & IntMask) - (y[iV] & IntMask) + borrow;

            x[iT] = (int)m;

            iV--;
            iT--;

            borrow = m < 0 ? -1 : 0;
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

    public Big Subtract(Big val)
    {
        if (val._sign == 0 || val._magnitude.Length == 0)
        {
            return this;
        }

        if (_sign == 0 || _magnitude.Length == 0)
        {
            return val.Negate();
        }

        if (val._sign < 0)
        {
            if (_sign > 0)
                return Add(val.Negate());
        }
        else
        {
            if (_sign < 0)
                return Add(val.Negate());
        }

        Big bigOne, littleOne;
        var compare = CompareTo(val);
        switch (compare)
        {
            case 0:
                return Zero;
            case < 0:
                bigOne = val;
                littleOne = this;
                break;
            default:
                bigOne = this;
                littleOne = val;
                break;
        }

        var res = new int[bigOne._magnitude.Length];

        Array.Copy(bigOne._magnitude, 0, res, 0, res.Length);

        return new Big(_sign * compare, Subtract(0, res, 0, littleOne._magnitude));
    }


    public byte[] MagnitudeBytes()
    {
        if (_magnitude.Length < 1) return Array.Empty<byte>();

        // 'fast' path for encoding (will always be 2 bytes or less)
        if (_magnitude.Length == 1)
        {
            var m = _magnitude[0];
            if (m < 1 << 16)
            {
                var result = new byte[2];
                result[0] = (byte)((m >> 8) & 0xff);
                result[1] = (byte)((m >> 0) & 0xff);

                return result;
            }
        }

        // normal path
        var accum = new List<byte>();

        var hit = false; // have we got to the most significant non-zero byte?

        // Go through all bytes in the magnitude data
        for (var i = 0; i < _magnitude.Length; i++)
        {
            var mx = _magnitude[i];
            for (var j = 24; j >= 0; j -= 8)
            {
                var b = (mx >> j) & 0xff;
                if (b == 0 && !hit) continue;

                hit = true;
                accum.Add((byte)b);
            }
        }

        return accum.ToArray();
    }

    public static readonly Big Zero = new(0, Array.Empty<byte>());
    private static readonly Big _one = ValueOf(1);

    public static Big ValueOf(long val)
    {
        if (val == 0)
        {
            return Zero;
        }

        // store val into a byte array
        var b = new byte[8];
        for (var i = 0; i < 8; i++)
        {
            b[7 - i] = (byte)val;
            val >>= 8;
        }

        return new Big(b);
    }
}
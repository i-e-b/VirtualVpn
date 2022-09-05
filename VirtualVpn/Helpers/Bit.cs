// ReSharper disable BuiltInTypeReferenceStyle

using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace VirtualVpn.Helpers;

/// <summary>
/// Byte and bit twiddling
/// </summary>
public static class Bit
{
    /// <summary>
    /// Read bytes from start to end (inclusive) into long, in network order
    /// </summary>
    public static UInt64 Unpack(byte[] source, int startIdx, int endIdx)
    {
        var result = 0UL;

        for (var i = startIdx; i <= endIdx; i++)
        {
            result <<= 8;
            result |= source[i];
        }
        
        return result;
    }

    /// <summary>
    /// Read an unsigned short from a byte array offset, and update the offset
    /// </summary>
    public static UInt16 ReadUInt16(byte[] data, ref int idx)
    {
        var length = (ushort)(data[idx++] << 8);
           length |= (ushort)(data[idx++] << 0);
        return length;
    }

    
    private static readonly Random _rnd = new();
    public static ulong RandomSpi() => (ulong)_rnd.NextInt64();

    public static void WriteUInt16(ushort value, byte[] data, ref int idx)
    {
        data[idx++] = (byte)((value >> 8) & 0xff);
        data[idx++] = (byte)((value >> 0) & 0xff);
    }

    public static ulong ReadUInt64(byte[] data, ref int idx)
    {
        var result = 0ul;
        result |= (ulong)data[idx++] << 56;
        result |= (ulong)data[idx++] << 48;
        result |= (ulong)data[idx++] << 40;
        result |= (ulong)data[idx++] << 32;
        
        result |= (ulong)data[idx++] << 24;
        result |= (ulong)data[idx++] << 16;
        result |= (ulong)data[idx++] <<  8;
        result |= (ulong)data[idx++] <<  0;
        return result;
    }
    
    public static int ReadInt32(byte[] data, ref int idx)
    {
        var result = 0;
        result |= data[idx++] << 24;
        result |= data[idx++] << 16;
        result |= data[idx++] << 8;
        result |= data[idx++] << 0;
        return result;
    }
    
    public static uint ReadUInt32(byte[] data, ref int idx)
    {
        var result = 0u;
        result |= (uint)data[idx++] << 24;
        result |= (uint)data[idx++] << 16;
        result |= (uint)data[idx++] << 8;
        result |= (uint)data[idx++] << 0;
        return result;
    }

    /// <summary>
    /// Higher security random bytes for N-once 
    /// </summary>
    public static byte[] RandomNonce()
    {
        var result = new byte[32];
        RandomNumberGenerator.Fill(result);
        return result;
    }

    /// <summary>
    /// Low security random bytes
    /// </summary>
    public static byte[] RandomBytes(int count)
    {
        var result = new byte[count];
        _rnd.NextBytes(result);
        return result;
    }


    public static byte[] UInt16ToBytes(ushort value)
    {
        var data = new byte[2];
        data[0] = (byte)((value >>  8) & 0xff);
        data[1] = (byte)((value >>  0) & 0xff);
        return data;
    }
    public static byte[] UInt32ToBytes(uint value)
    {
        var data = new byte[4];
        data[0] = (byte)((value >> 24) & 0xff);
        data[1] = (byte)((value >> 16) & 0xff);
        data[2] = (byte)((value >>  8) & 0xff);
        data[3] = (byte)((value >>  0) & 0xff);
        return data;
    }
    
    public static UInt32 BytesToUInt32(byte[] bytes)
    {
        UInt32 result = 0;
        
        result |= (uint)bytes[0] << 24;
        result |= (uint)bytes[1] << 16;
        result |= (uint)bytes[2] <<  8;
        result |= (uint)bytes[3] <<  0;
        
        return result;
    }
    
    /// <summary>
    /// Read most significant bytes first from data, filling in
    /// as much of a 64-bit integer as possible,
    /// starting at most significant byte of output.
    /// Will stop after 8 bytes, OR if data is exhausted.
    /// </summary>
    public static ulong BytesToUInt64Msb(byte[] data)
    {
        var result = 0ul;
        var idx = 0;
        var end = data.Length;
        result |= (ulong)data[idx++] << 56;
        if (idx >= end) return result;
        result |= (ulong)data[idx++] << 48;
        if (idx >= end) return result;
        result |= (ulong)data[idx++] << 40;
        if (idx >= end) return result;
        result |= (ulong)data[idx++] << 32;
        if (idx >= end) return result;
        
        result |= (ulong)data[idx++] << 24;
        if (idx >= end) return result;
        result |= (ulong)data[idx++] << 16;
        if (idx >= end) return result;
        result |= (ulong)data[idx++] <<  8;
        if (idx >= end) return result;
        result |= (ulong)data[idx  ] <<  0;
        return result;
    }
    
    public static void WriteUInt32(uint value, byte[] data, ref int idx)
    {
        data[idx++] = (byte)((value >> 24) & 0xff);
        data[idx++] = (byte)((value >> 16) & 0xff);
        data[idx++] = (byte)((value >>  8) & 0xff);
        data[idx++] = (byte)((value >>  0) & 0xff);
    }

    public static void WriteUInt64(ulong value, byte[] data, ref int idx)
    {
        data[idx++] = (byte)((value >> 56) & 0xff);
        data[idx++] = (byte)((value >> 48) & 0xff);
        data[idx++] = (byte)((value >> 40) & 0xff);
        data[idx++] = (byte)((value >> 32) & 0xff);
        
        data[idx++] = (byte)((value >> 24) & 0xff);
        data[idx++] = (byte)((value >> 16) & 0xff);
        data[idx++] = (byte)((value >>  8) & 0xff);
        data[idx++] = (byte)((value >>  0) & 0xff);
    }

    public static byte[] UInt64ToBytes(ulong value)
    {
        var data = new byte[8];
        
        data[0] = (byte)((value >> 56) & 0xff);
        data[1] = (byte)((value >> 48) & 0xff);
        data[2] = (byte)((value >> 40) & 0xff);
        data[3] = (byte)((value >> 32) & 0xff);
        
        data[4] = (byte)((value >> 24) & 0xff);
        data[5] = (byte)((value >> 16) & 0xff);
        data[6] = (byte)((value >>  8) & 0xff);
        data[7] = (byte)((value >>  0) & 0xff);
        
        return data;
    }

    /// <summary>
    /// Read an subset of bytes into a new array.
    /// `size = -1` means: to the end of source
    /// </summary>
    public static byte [] Subset(int size, byte[] source, ref int idx)
    {
        if (idx < 0) idx = source.Length - idx;
        if (size < 0) size = source.Length - idx;
        if (size == 0) return Array.Empty<byte>();
        if (idx + size > source.Length) throw new Exception("Invalid subset size: tried to read off the end of source");
        
        var result = new byte[size];

        for (int i = 0; i < size; i++)
        {
            result[i] = source[idx++];
        }
        
        return result;
    }
    /// <summary>
    /// Generate a description string in the same format as StrongSwan logs
    /// </summary>
    public static string Describe(string name, byte[]? bytes)
    {
        return Describe(name, bytes, 0, bytes?.Length ?? 0);
    }
    
    /// <summary>
    /// Generate a description string in the same format as StrongSwan logs
    /// </summary>
    public static string Describe(string name, byte[]? bytes, int offset, int length)
    {
        var end = offset+length;
        if (Settings.CodeModeForDescription)
        {
            name = Safe(name);
            if (bytes is null) return $"var {name} = new byte[0];";
            
            var sb = new StringBuilder();
            
            sb.Append("var ");
            sb.Append(name);
            sb.Append(" = new byte[] {");
            
            if (end > bytes.Length) end = bytes.Length;
            for (int b = offset; b < end; b++)
            {
                sb.Append($"0x{bytes[b]:X2}, ");
            }
            
            sb.Append("};");
            sb.AppendLine();
            
            return sb.ToString();
        }
        else
        {
            if (bytes is null)
            {
                return $"{name} => 0 bytes (null)\r\n";
            }

            var sb = new StringBuilder();

            sb.Append(name);
            sb.Append(" => ");
            sb.Append(bytes.Length);
            sb.Append("bytes");

            var idx = offset;
            if (end > bytes.Length) end = bytes.Length;
            while (idx < end)
            {
                sb.AppendLine();
                sb.Append($"{idx:d4}: ");
                for (int b = 0; (b < 16) && (idx < bytes.Length); b++)
                {
                    sb.Append($"{bytes[idx++]:X2} ");
                }
            }

            sb.AppendLine();
            return sb.ToString();
        }
    }

    /// <summary>
    /// Code friendly version of a string
    /// </summary>
    private static string Safe(string name)
    {
        var sb = new StringBuilder();

        var i = 0;
        foreach (var c in name)
        {
            switch (c)
            {
                case >= '0' and <= '9':
                    if (i==0) sb.Append('_');
                    i++;
                    sb.Append(c);
                    break;
                
                case >= 'a' and <= 'z':
                case >= 'A' and <= 'Z':
                case '_':
                    i++;
                    sb.Append(c);
                    break;
                
                case ' ':
                    i++;
                    sb.Append('_');
                    break;
            }
        }
        
        return sb.ToString();
    }

    public static byte[] ParseBytes(string pStr)
    {
        var accum = new List<byte>();

        for (int i = 0; i < pStr.Length; i += 2)
        {
            accum.Add(byte.Parse($"{pStr[i]}{pStr[i+1]}",NumberStyles.HexNumber));
        }
        
        return accum.ToArray();
    }

    public static byte[] HashSha1(byte[] secret)
    {
        var hash = SHA1.Create();
        return hash.ComputeHash(secret);
    }
    
    public static byte[] HashSha256(byte[] secret)
    {
        var hash = SHA256.Create();
        return hash.ComputeHash(secret);
    }

    public static string HexString(byte[]? authData)
    {
        if (authData is null) return "<null>";
        return string.Join("", authData.Select(b=>b.ToString("x2")));
    }

    public static bool AreDifferent(byte[] bytes1, byte[] bytes2)
    {
        if (bytes1.Length != bytes2.Length) return false;
        var same = true;
        for (int i = 0; i < bytes1.Length; i++)
        {
            same &= bytes1[i] == bytes2[i];
        }
        return !same;
    }

    /// <summary>
    /// Copy the entirety of 'src' on top of 'dst', at a given offset into dst.
    /// Will stop if either array is exhausted.
    /// </summary>
    public static void CopyOver(byte[] src, byte[] dst, ref int dstOffset)
    {
        for (int i = 0; i < src.Length && dstOffset < dst.Length; i++)
        {
            dst[dstOffset++] = src[i];
        }
    }

    public static string BinString(byte b) => Convert.ToString(b, 2).PadLeft(8, '0');
    public static string BinString(int b) => Convert.ToString(b, 2);

    public static string ToIpAddressString(byte[] bytes)
    {
        if (bytes.Length == 4) return $"{bytes[0]}.{bytes[1]}.{bytes[2]}.{bytes[3]}";
        return HexString(bytes);
    }

    public static string SafeString(IEnumerable<byte> bytes)
    {
        var sb = new StringBuilder();

        foreach (var t in bytes)
        {
            var c = (char)t;
            if (c == '\r' || c == '\n') sb.Append(c);
            else if (c >= ' ' && c <= '~') sb.Append(c);
            else sb.Append('.');
        }
        
        return sb.ToString();
    }
}
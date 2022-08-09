// ReSharper disable BuiltInTypeReferenceStyle

using System.Globalization;
using System.Text;

namespace RawSocketTest.Helpers;

/// <summary>
/// Byte and bit twiddling
/// </summary>
public static class Bit
{
    /// <summary>
    /// Read a byte from a larger integer
    /// </summary>
    public static byte PickByte(int byteIndex, ulong data)
    {
        var s = 8 * (byteIndex - 1);
        return (byte)((data >> s) & 0xff);
    }

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

    public static byte[] RandomNonce()
    {
        // TODO: use System.Security.Cryptography.RandomNumberGenerator  ?
        var result = new byte[32];
        _rnd.NextBytes(result);
        return result;
    }

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
    /// Read an subset of bytes into a new array
    /// </summary>
    public static byte [] Subset(int size, byte[] source, ref int idx)
    {
        if (size < 0) throw new Exception("Invalid subset size: must be zero or greater");
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
        if (bytes is null)
        {
            return $"{name} => 0 bytes (null)\r\n";
        }

        var sb = new StringBuilder();
        
        sb.Append(name);
        sb.Append(" => ");
        sb.Append(bytes.Length);
        sb.Append("bytes");
        
        var idx = 0;
        while (idx < bytes.Length)
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

    public static byte[] ParseBytes(string pstr)
    {
        var accum = new List<byte>();

        for (int i = 0; i < pstr.Length; i += 2)
        {
            accum.Add(byte.Parse($"{pstr[i]}{pstr[i+1]}",NumberStyles.HexNumber));
        }
        
        return accum.ToArray();
    }
}
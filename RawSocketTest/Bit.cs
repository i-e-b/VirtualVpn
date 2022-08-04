// ReSharper disable BuiltInTypeReferenceStyle
namespace RawSocketTest;

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
}
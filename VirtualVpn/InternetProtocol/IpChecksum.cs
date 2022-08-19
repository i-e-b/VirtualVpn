namespace VirtualVpn.InternetProtocol;

public static class IpChecksum
{
    /// <summary>
    /// Calculate the checksum of the raw data.
    /// If the checksum is in place and correct, this will return zero.
    /// If the checksum is zeroed, this will give the correct value to inject
    /// </summary>
    public static ushort CalculateChecksum(byte[] raw)
    {
        return SharedChecksum(raw, raw.Length, 0);
    }

    /// <summary>
    /// TCP specific checksum
    /// </summary>
    public static ushort TcpChecksum(byte[] sourceAddress, byte[] destAddress, byte protocol,
        int length, byte[] message, int offset)
    {
        var bufferLength = length + 12;

        var odd = length % 2 == 1;
        if (odd) ++bufferLength;

        var buffer = new byte[bufferLength];

        buffer[0] = sourceAddress[0];
        buffer[1] = sourceAddress[1];
        buffer[2] = sourceAddress[2];
        buffer[3] = sourceAddress[3];

        buffer[4] = destAddress[0];
        buffer[5] = destAddress[1];
        buffer[6] = destAddress[2];
        buffer[7] = destAddress[3];

        buffer[8] = 0;
        buffer[9] = protocol;

        UShortToBytes((ushort)length, buffer, 10);

        var i = 11;
        while (++i < length + 12)
        {
            buffer[i] = message[i + offset - 12];
        }

        if (odd) buffer[i] = 0;

        return SharedChecksum(buffer, buffer.Length, 0);
    }

    private static void UShortToBytes(ushort value, byte[] buffer, int offset)
    {
        buffer[offset + 1] = (byte)(value & 0xff);
        value = (ushort)(value >> 8);
        buffer[offset] = (byte)value;
    }

    private static ushort SharedChecksum(byte[] message, int length, int offset)
    {
        // Sum consecutive 16-bit words.
        ulong sum = 0;

        while (offset < length - 1)
        {
            sum += IntegralFromBytes(message, offset, 2);
            offset += 2;
        }

        if (offset == length - 1)
        {
            sum += ((ulong)message[offset]) << 8;
        }

        // Add upper 16 bits to lower 16 bits.
        sum = (sum >> 16) + (sum & 0xffff);

        // Add carry
        sum += sum >> 16;

        // Ones complement and truncate.
        return (ushort)~sum;
    }

    private static ulong IntegralFromBytes(byte[] buffer, int offset, int length)
    {
        ulong answer = 0;

        while (--length >= 0)
        {
            answer <<= 8;
            answer |= buffer[offset];
            ++offset;
        }

        return answer;
    }
}
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
        if (raw.Length < 2) throw new Exception($"Invalid length {raw.Length}");
        
        ulong sum = 0;
        var i = 0;
        // main words
        for (; i+1 < raw.Length; i+=2)
        {
            var word = (uint)((raw[i] << 8) | raw[i+1]);
            sum += word;
        }

        // trailing byte
        if (i < raw.Length - 1)
        {
            sum += raw[i];
        }

        // folding
        while ((sum >> 16) > 0)
        {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        // bitwise flip
        return (ushort)~((ushort)sum);
    }
}
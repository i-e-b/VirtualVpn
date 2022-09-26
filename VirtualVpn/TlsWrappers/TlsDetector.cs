using System.Diagnostics.CodeAnalysis;

namespace VirtualVpn.TlsWrappers;

/// <summary>
/// Helper to detect TLS packets in TCP/IP streams
/// </summary>
public static class TlsDetector
{
    /// <summary>
    /// Number of bytes that must be available
    /// before a TLS 'hello' message can be detected
    /// </summary>
    public const int RequiredBytes = 11;

    /// <summary>
    /// Returns true if the incoming data looks like a TLS/SSL client handshake.
    /// Gives an additional flag that is true only if it is a TLS version (SSL 3.1+)
    /// <p></p>
    /// This only needs 11 bytes from the start of the client's TCP/IP stream.
    /// </summary>
    public static bool IsTlsHandshake(IEnumerable<byte> incoming, out bool acceptableVersion)
    {
        acceptableVersion = false;
        
        var headers = incoming.Take(11).ToArray();
        if (headers.Length < 11) return false;
        
        var recordType = (TlsRecordType)headers[0];
        var sslVersion = (SslVersion)((headers[1] << 8) | headers[2]);
        var recordLength = (headers[3] << 8) | headers[4];
        
        var handshakeType = (TlsHandshakeType)headers[5];
        var handshakeLength = (headers[6] << 16) | (headers[7] << 8) | headers[8];
        var sslVersionHandshake = (SslVersion)((headers[9] << 8) | headers[10]);
        
        Log.Trace("Inspecting incoming TCP/IP message for TLS markers");
        Log.Trace($"Record type={recordType.ToString()}, SSL version={sslVersion.ToString()}, record length={recordLength}");
        Log.Trace($"Handshake type={handshakeType.ToString()}, SSL version={sslVersionHandshake.ToString()}, handshake length={handshakeLength}");

        acceptableVersion = sslVersion == SslVersion.Tls1 || sslVersion == SslVersion.Tls2 || sslVersion == SslVersion.Tls3;
        
        return    recordType    == TlsRecordType.Handshake
               && handshakeType == TlsHandshakeType.ClientHello
               && sslVersion    == sslVersionHandshake
               && recordLength  == (handshakeLength + 4);
    }
    
    [SuppressMessage("ReSharper", "UnusedMember.Local")]
    private enum TlsRecordType
    {
        Invalid = 0,
        ChangeCipherSpec = 0x14,
        Alert = 0x15,
        Handshake = 0x16,
        ApplicationData = 0x17
    }
    
    [SuppressMessage("ReSharper", "UnusedMember.Local")]
    private enum TlsHandshakeType
    {
        Invalid = 0,
        ClientHello = 0x01,
        ServerHello = 0x02,
        Certificate = 0x0B,
        ServerKeyEx = 0x0C,
        ClientKeyEx = 0x10
    }

    [SuppressMessage("ReSharper", "UnusedMember.Local")]
    private enum SslVersion
    {
        Invalid = 0,
        Ssl3 = 0x03_00,
        Tls1 = 0x03_01,
        Tls2 = 0x03_02,
        Tls3 = 0x03_03
    }

}
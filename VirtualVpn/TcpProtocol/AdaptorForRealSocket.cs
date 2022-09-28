using System.Net.Sockets;

namespace VirtualVpn.TcpProtocol;

internal class AdaptorForRealSocket : ISocketAdaptor
{
    private readonly Socket _socket;

    public AdaptorForRealSocket(Socket socket)
    {
        _socket = socket;
    }

    public void Dispose() => _socket.Dispose();

    public void Close() => _socket.Close();

    public bool Connected => _socket.Connected;
    public int Available => _socket.Available;
    public int IncomingFromTunnel(byte[] buffer, int offset, int length)
    {
        try
        {
            return _socket.Send(buffer, offset, length, SocketFlags.None);
        }
        catch (Exception ex)
        {
            Log.Error("Writing to socket failed", ex);
            return 0;
        }
    }

    public int OutgoingFromLocal(byte[] buffer)
    {
        try
        {
            return _socket.Receive(buffer);
        }
        catch (Exception ex)
        {
            Log.Error("Reading from socket failed", ex);
            return 0;
        }
    }
}
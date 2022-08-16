using System.Net;
using System.Net.Sockets;
using System.Text;

namespace RawSocketTest.Helpers;

public class TcpEcho
{
    private readonly TcpListener _tcpClient;
    private readonly Thread _listenThread;
    private readonly int _port;

    // using UTF8 encoding for the messages
    static Encoding encoding = Encoding.UTF8;
    
    public TcpEcho(int port)
    {
        _port = port;
        _tcpClient = new TcpListener(new IPEndPoint(IPAddress.Any, port));
        
        _listenThread = new Thread(RunListener){IsBackground = true};
        _listenThread.Start();
    }

    private void RunListener()
    {
        _tcpClient.Start();
        while (_listenThread.IsAlive)
        {
            var sender = _tcpClient.AcceptTcpClient();
            var request = streamToMessage(sender.GetStream());
            Log.Critical($"Got a TCP connection! (port {_port})");
            if (request != null)
            {
                var responseMessage = MessageHandler(request);
                sendMessage(responseMessage, sender);
            }
        }
    }
    
    private static void sendMessage(string message, TcpClient client)
    {
        // messageToByteArray- discussed later
        var bytes = messageToByteArray(message);
        client.GetStream().Write(bytes, 0, bytes.Length);
    }
 
    public static string MessageHandler(string message)
    {
        Console.WriteLine("Received message: " + message);
        return "Thank a lot for the message!";
    }

    private static byte[] messageToByteArray(string message)
    {
        // get the size of original message
        var messageBytes = encoding.GetBytes(message);
        var messageSize = messageBytes.Length;
        // add content length bytes to the original size
        var completeSize = messageSize + 4;
        // create a buffer of the size of the complete message size
        var completemsg = new byte[completeSize];
 
        // convert message size to bytes
        var sizeBytes = BitConverter.GetBytes(messageSize);
        // copy the size bytes and the message bytes to our overall message to be sent 
        sizeBytes.CopyTo(completemsg, 0);
        messageBytes.CopyTo(completemsg, 4);
        return completemsg;
    }
    private static string? streamToMessage(Stream stream)
    {
        // size bytes have been fixed to 4
        var sizeBytes = new byte[4];
        // read the content length
        _ = stream.Read(sizeBytes, 0, 4);
        var messageSize = BitConverter.ToInt32(sizeBytes, 0);
        if (messageSize > 10240) return null;
        
        // create a buffer of the content length size and read from the stream
        var messageBytes = new byte[messageSize];
        _ = stream.Read(messageBytes, 0, messageSize);
        
        // convert message byte array to the message string using the encoding
        var message = encoding.GetString(messageBytes);
        string? result = null;
        foreach (var c in message)
            if (c != '\0')
                result += c;
 
        return result;
    }
}
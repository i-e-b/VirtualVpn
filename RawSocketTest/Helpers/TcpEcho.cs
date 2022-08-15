using System.Net;
using System.Net.Sockets;
using System.Text;

namespace RawSocketTest.Helpers;

public class TcpEcho
{
    private readonly Socket _sock;
    private readonly TcpListener _tcpClient;
    private readonly Thread _listenThread;
    private readonly int _port;

    // using UTF8 encoding for the messages
    static Encoding encoding = Encoding.UTF8;
    
    public TcpEcho(int port)
    {
        _port = port;
        _tcpClient = new TcpListener(new IPEndPoint(IPAddress.Any, port));
        
        _listenThread = new Thread(() => { RunListener(); }){IsBackground = true};
        _listenThread.Start();
    }

    private void RunListener()
    {
        _tcpClient.Start();
        while (true)
        {
            var sender = _tcpClient.AcceptTcpClient();
            string request = streamToMessage(sender.GetStream());
            Log.Critical($"Got a TCP connection! (port {_port})");
            if (request != null)
            {
                string responseMessage = MessageHandler(request);
                sendMessage(responseMessage, sender);
            }
        }
    }
    
    private static void sendMessage(string message, TcpClient client)
    {
        // messageToByteArray- discussed later
        byte[] bytes = messageToByteArray(message);
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
        byte[] messageBytes = encoding.GetBytes(message);
        int messageSize = messageBytes.Length;
        // add content length bytes to the original size
        int completeSize = messageSize + 4;
        // create a buffer of the size of the complete message size
        byte[] completemsg = new byte[completeSize];
 
        // convert message size to bytes
        byte[] sizeBytes = BitConverter.GetBytes(messageSize);
        // copy the size bytes and the message bytes to our overall message to be sent 
        sizeBytes.CopyTo(completemsg, 0);
        messageBytes.CopyTo(completemsg, 4);
        return completemsg;
    }
    private static string streamToMessage(Stream stream)
    {
        // size bytes have been fixed to 4
        byte[] sizeBytes = new byte[4];
        // read the content length
        stream.Read(sizeBytes, 0, 4);
        int messageSize = BitConverter.ToInt32(sizeBytes, 0);
        // create a buffer of the content length size and read from the stream
        byte[] messageBytes = new byte[messageSize];
        stream.Read(messageBytes, 0, messageSize);
        // convert message byte array to the message string using the encoding
        string message = encoding.GetString(messageBytes);
        string result = null;
        foreach (var c in message)
            if (c != '\0')
                result += c;
 
        return result;
    }
}
﻿using System.Diagnostics;
using System.Net;
using System.Text;
using RawSocketTest.Enums;
using RawSocketTest.EspProtocol;
using RawSocketTest.Helpers;
using RawSocketTest.InternetProtocol;

namespace RawSocketTest.TransmissionControlProtocol;

/// <summary>
/// Manages a single TCP session over a virtual connection through a ChildSA tunnel.
/// https://en.wikipedia.org/wiki/Transmission_Control_Protocol
/// </summary>
/// <remarks>
/// The dotnet built-in TCP/IP stack seems completely tied to using
/// the physical network, so we have to roll our own.
/// </remarks>
public class TcpSession
{
    /// <summary>
    /// The tunnel gateway we expect to be talking to
    /// </summary>
    public IPEndPoint Gateway { get; }

    /// <summary>
    /// The tunnel session we are connected to (used for sending replies)
    /// </summary>
    private readonly ChildSa _transport;

    /// <summary>
    /// Current session state
    /// </summary>
    public TcpSocketState State { get; set; }

    /// <summary>
    /// Time since last packets send or received.
    /// Only starts ticking when first packets transmitted.
    /// </summary>
    public Stopwatch LastContact { get; set; }

    /// <summary>
    /// Address of remote side
    /// </summary>
    public byte[] RemoteAddress { get; private set; } = Array.Empty<byte>();

    /// <summary>
    /// Port declared by remote side
    /// </summary>
    public int RemotePort { get; private set; }

    /// <summary>
    /// Address requested for this session
    /// </summary>
    public byte[] LocalAddress { get; private set; } = Array.Empty<byte>();

    /// <summary>
    /// Local port requested for this session
    /// </summary>
    public int LocalPort { get; private set; }
    
    private long _localSeq, _remoteSeq;
    private static Random _rnd = new();

    public TcpSession(ChildSa transport, IPEndPoint gateway)
    {
        _transport = transport;
        Gateway = gateway;
        
        State = TcpSocketState.Closed;
        LastContact = new Stopwatch();
    }

    /// <summary>
    /// Initiate a connection from a first incoming packet
    /// </summary>
    public bool Start(IpV4Packet ipv4)
    {
        AssertState(TcpSocketState.Closed);
        Log.Debug("TCP session initiation");

        // ready to act as a server
        _localSeq = _rnd.Next(100, 65000); // random sequence for our side
        State = TcpSocketState.Listen;

        var ok = HandleMessage(ipv4, out var tcp);
        if (!ok)
        {
            Log.Debug("TCP session initiation failed");
            State = TcpSocketState.Closed;
            return false;
        }

        LastContact.Start(); // start counting. This gets reset every time we get another message

        // capture identity
        LocalAddress = ipv4.Destination.Value;
        LocalPort = tcp.DestinationPort;
        RemotePort = tcp.SourcePort;
        RemoteAddress = ipv4.Source.Value;

        Log.Debug("TCP session initiation completed:" +
                  $" remote={Bit.ToIpAddressString(RemoteAddress)}:{RemotePort}," +
                  $" local={Bit.ToIpAddressString(LocalAddress)}:{LocalPort}");

        return true;
    }

    /// <summary>
    /// Continue a session with a packet from the remote
    /// </summary>
    public void Accept(IpV4Packet ipv4)
    {
        LastContact.Restart(); // back to zero, keep counting
        HandleMessage(ipv4, out _);
    }
    
    /// <summary>
    /// Read payload of an IPv4 packet to determine the source address
    /// and sender port. This is used to uniquely key sessions.
    /// </summary>
    public static SenderPort ReadSenderAndPort(IpV4Packet message)
    {
        var ok = ByteSerialiser.FromBytes<TcpSegment>(message.Payload, out var tcpSeg);

        if (!ok) return new SenderPort(Array.Empty<byte>(), 0);

        return new SenderPort(message.Source.Value, tcpSeg.DestinationPort);
    }

    public void Close()
    {
        // TODO: shut down this connection
    }

    private bool HandleMessage(IpV4Packet ipv4, out TcpSegment tcp)
    {
        // read the TCP segment
        var ok = ByteSerialiser.FromBytes(ipv4.Payload, out tcp);
        if (!ok)
        {
            Log.Warn("TCP payload did not parse");
            Log.Debug(Bit.Describe("ipv4 payload", ipv4.Payload));
            return false;
        }
        
        // TODO: double check that incoming is for the session we expect?

        switch (State)
        {
            case TcpSocketState.Closed:
                throw new Exception("Tried to communicate with a closed connection");

            case TcpSocketState.Listen: // Expect to receive a SYN message and move to SynReceived

                if (tcp.Flags != TcpSegmentFlags.Syn) throw new Exception($"Invalid flags. Local state={State.ToString()}, request flags={tcp.Flags.ToString()}");
                _remoteSeq = tcp.SequenceNumber + 1;

                var replyPkt = new TcpSegment
                {
                    SourcePort = tcp.DestinationPort,
                    DestinationPort = tcp.SourcePort,
                    SequenceNumber = _localSeq,
                    AcknowledgmentNumber = _remoteSeq,
                    DataOffset = 5,
                    Reserved = 0,
                    Flags = TcpSegmentFlags.SynAck,
                    WindowSize = tcp.WindowSize,
                    Options = Array.Empty<byte>(),
                    Payload = Array.Empty<byte>()
                };
                Reply(sender: ipv4, message: replyPkt);
                State = TcpSocketState.SynReceived; // other side should switch to Established.

                break;
            case TcpSocketState.SynReceived: // Expect to receive an ACK message and move to Established

                if (tcp.Flags != TcpSegmentFlags.Ack) throw new Exception($"Invalid flags. Local state={State.ToString()}, request flags={tcp.Flags.ToString()}");

                if (tcp.SequenceNumber != _remoteSeq) Log.Warn($"Request out of sequence: Expected {_remoteSeq}, got {tcp.SequenceNumber}");
                if (tcp.AcknowledgmentNumber != _localSeq) Log.Warn($"Acknowledgement out of sequence: Expected {_localSeq}, got {tcp.AcknowledgmentNumber}");

                State = TcpSocketState.Established;

                break;

            case TcpSocketState.Established:
                // We should either get an empty ACK message (end of handshake)
                // OR an ACK message with data (streaming)

                if (tcp.Flags != TcpSegmentFlags.Ack) throw new Exception($"Invalid flags. Local state={State.ToString()}, request flags={tcp.Flags.ToString()}");

                if (tcp.Payload.Length > 0)
                {
                    Log.Critical("PAY-DIRT!\r\n"+Encoding.ASCII.GetString(tcp.Payload));
                }

                break;
            
            // TODO: manage these states
            case TcpSocketState.FinWait1:
            case TcpSocketState.FinWait2:
            case TcpSocketState.CloseWait:
            case TcpSocketState.Closing:
            case TcpSocketState.LastAck:
            case TcpSocketState.TimeWait:
            case TcpSocketState.SynSent:
                Log.Info($"state not yet managed: {State.ToString()}");
                break;
            default:
                throw new ArgumentOutOfRangeException();
        }

        Log.Warn($"From {ipv4.Source.AsString}:{tcp.SourcePort} to {ipv4.Destination.AsString}:{tcp.DestinationPort}");
        Log.Warn($"Flags: {tcp.Flags.ToString()}, seq={tcp.SequenceNumber}, ack={tcp.AcknowledgmentNumber}");


        //var reply = new IpV4Packet();
        //_transport.Send(reply, Gateway);
        return true;
    }

    /// <summary>
    /// Send a reply through the connected gateway, back to original sender,
    /// with a new message. This increments local sequence number.
    /// </summary>
    private void Reply(IpV4Packet sender, TcpSegment message)
    {
        _localSeq++;
        
        // Set message checksum
        message.UpdateChecksum(sender.Destination.Value, sender.Source.Value, IpV4Protocol.TCP);
        var tcpPayload = ByteSerialiser.ToBytes(message);
        
        // prepare container
        var reply = new IpV4Packet
        {
            Version = IpV4Version.Version4,
            HeaderLength = 5,
            ServiceType = 0,
            TotalLength = 20 + tcpPayload.Length,
            PacketId = _rnd.Next(10, 32700),
            Flags = IpV4HeaderFlags.None,
            FragmentIndex = 0,
            Ttl = 64,
            Protocol = IpV4Protocol.TCP,
            Checksum = 0,
            Source = sender.Destination,
            Destination = sender.Source,
            Options = Array.Empty<byte>(),
            Payload = tcpPayload
        };
        
        reply.UpdateChecksum();
        
        _transport.Send(reply, Gateway);
    }


    private void AssertState(TcpSocketState expected)
    {
        if (State != expected) throw new Exception($"Invalid state. Expected {expected.ToString()}, got {State.ToString()}");
    }
}
﻿using System.Diagnostics;
using System.Net;
using VirtualVpn.InternetProtocol;

namespace VirtualVpn.TcpProtocol;

public interface ITcpAdaptor: IDisposable
{
    /// <summary>
    /// The socket is closed. Adaptor should stop event pump
    /// and no longer route any packets to the socket.
    /// </summary>
    void Close();
    
    /// <summary>
    /// The socket is closing.
    /// Adaptor should pump events while the session end handshake happens
    /// </summary>
    void Closing();
    
    /// <summary>
    /// Send data through the tunnel
    /// </summary>
    void Reply(TcpSegment seg, TcpRoute route);
    
    /// <summary>
    /// Continue a session with a packet from the remote
    /// </summary>
    void Accept(IpV4Packet ipv4);
    
    /// <summary>
    /// Trigger time-based actions.
    /// This should be called periodically
    /// <p></p>
    /// Returns true if any action was taken.
    /// </summary>
    bool EventPump();

    /// <summary>
    /// The sender IP and Port number that uniquely identifies an active connection
    /// </summary>
    SenderPort SelfKey { get; }
    
    /// <summary>
    /// Time since last packets send or received.
    /// Only starts ticking when first packets transmitted.
    /// </summary>
    Stopwatch LastContact { get; }
    
    /// <summary>
    /// Time that the connection started.
    /// This is never reset, and is used as a hard-stop for sessions.
    /// </summary>
    DateTime StartTime { get; }

    /// <summary> Address requested for this session </summary>
    byte[] LocalAddress { get; }
    
    /// <summary> TcpSocket that represents the connection through the ChildSa tunnel </summary>
    TcpSocket SocketThroughTunnel { get; }

    /// <summary> Local port requested for this session </summary>
    int LocalPort { get; }

    /// <summary> Address of remote side </summary>
    byte[] RemoteAddress { get; }

    /// <summary> Port declared by remote side </summary>
    int RemotePort { get; }

    /// <summary> The tunnel gateway we expect to be talking to </summary>
    IPEndPoint Gateway { get; }

    /// <summary>
    /// Return true if the tunnel-side connection is in a state where we don't expect
    /// any further data
    /// </summary>
    bool TunnelConnectionIsClosedOrFaulted();
    
    /// <summary>
    /// Return true if there was a connection fault on the Web-app side
    /// </summary>
    bool WebAppConnectionIsFaulted();
    
    /// <summary>
    /// Provide a human-readable description of the adaptor
    /// </summary>
    string Describe();
    
    
    /// <summary>
    /// Notify the adaptor that a connection was terminated at an unexpected point.
    /// This is part of the <see cref="VpnServer.AlarmIsActive"/> system.
    /// </summary>
    void ConnectionRemoteTerminated();
    
    /// <summary>
    /// Notify the adaptor that a connection was fully established in a normal way.
    /// This is part of the <see cref="VpnServer.AlarmIsActive"/> system.
    /// </summary>
    void ConnectionNormal();
}
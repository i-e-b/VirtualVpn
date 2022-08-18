// ReSharper disable InconsistentNaming
// ReSharper disable IdentifierTypo
// ReSharper disable UnusedMember.Global
// ReSharper disable CommentTypo
namespace RawSocketTest.Enums;

/// <summary>
/// Protocol as defined in IP packets.
/// See https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
/// <p></p>
/// This is not an exhaustive list
/// </summary>
public enum IpV4Protocol : byte
{
    /// <summary>
    /// IPv6 Hop-by-Hop Option
    /// RFC 8200
    /// </summary>
    HOPOPT = 0,

    /// <summary>
    /// Internet Control Message Protocol (ping)
    /// RFC 792
    /// </summary>
    ICMP = 1,

    /// <summary>
    /// Internet Group Management Protocol
    /// RFC 1112
    /// </summary>
    IGMP = 2,

    /// <summary>
    /// Gateway-to-Gateway Protocol
    /// RFC 823
    /// </summary>
    GGP = 3,

    /// <summary>
    /// IP in IP (encapsulation)
    /// RFC 2003
    /// </summary>
    IpInIp = 4,

    /// <summary>
    /// Internet Stream Protocol
    /// RFC 1190, RFC 1819
    /// </summary>
    ST = 5,

    /// <summary>
    /// Transmission Control Protocol
    /// RFC 793
    /// </summary>
    TCP = 6,

    /// <summary>
    /// Core-based trees
    /// RFC 2189
    /// </summary>
    CBT = 7,

    /// <summary>
    /// Exterior Gateway Protocol
    /// RFC 888
    /// </summary>
    EGP = 8,

    /// <summary>
    /// Or IGRP; Interior Gateway Protocol (any private interior gateway)
    /// </summary>
    IGP = 9,

    /// <summary>
    /// BBN RCC Monitoring
    /// </summary>
    BBN_RCC_MON = 10,

    /// <summary>
    /// Network Voice Protocol
    /// RFC 741
    /// </summary>
    NVP2 = 11,
    
    /// <summary>
    /// Xerox PUP (historical)
    /// </summary>
    PUP=12,
    
    /// <summary>
    /// ARGUS (historical?)
    /// </summary>
    ARGUS=13,
    
    /// <summary>
    /// EMCON (historical?)
    /// </summary>
    EMCON=14,
    
    /// <summary>
    /// Cross Net Debugger
    /// IEN 158
    /// </summary>
    XNET=15,
    
    /// <summary>
    /// ChaosNet (historical?)
    /// </summary>
    CHAOS=16,
    
    /// <summary>
    /// User Datagram Protocol
    /// RFC 768
    /// </summary>
    UDP=17,
    
    /// <summary>
    /// IPv6 Encapsulation (6to4 and 6in4)
    /// RFC 2473
    /// </summary>
    IPv6=41,
    
    /// <summary>
    /// (VPN) Generic Routing Encapsulation
    /// RFC 2784, RFC 2890
    /// </summary>
    GRE=47,
    
    /// <summary>
    /// (VPN) Encapsulating Security Payload
    /// RFC 4303
    /// </summary>
    ESP=50,
    
    /// <summary>
    /// (VPN) Authentication Header
    /// RFC 4302
    /// </summary>
    AH=51,
    
    /// <summary>
    /// IPv6 encapsulation
    /// RFC 2473
    /// </summary>
    ENCAP=41,
    
    /// <summary>
    /// Transport Layer Security Protocol
    /// </summary>
    TLSP=56,
    
    /// <summary>
    /// ICMP for IPv6
    /// RFC 4443, RFC 4884
    /// </summary>
    IPv6ICMP=58,
    
    /// <summary>
    /// No Next Header for IPv6
    /// RFC 8200
    /// </summary>
    IPv6NoNxt=59,
    
    /// <summary>
    /// Destination Options for IPv6
    /// RFC 8200
    /// </summary>
    IPv6Opts=60,
    
    /// <summary>
    /// Reserved for any host internal protocol
    /// </summary>
    Internal=61,
    
    /// <summary>
    /// Reserved for any local network protocol
    /// </summary>
    Local=63,
    
    /// <summary>
    /// Reserved for any distributed file system protocol
    /// </summary>
    FileSystem=68,
    
    /// <summary>
    /// Open Shortest Path First
    /// RFC 2328
    /// </summary>
    OSPF=89,
    
    /// <summary>
    /// (VPN) Virtual Router Redundancy Protocol
    /// </summary>
    VRRP=112,
    
    /// <summary>
    /// (VPN) Layer Two Tunneling Protocol Version 3
    /// RFC 3931
    /// </summary>
    L2TP=115,
    
    /// <summary>
    /// Stream Control Transmission Protocol
    /// RFC 4960
    /// </summary>
    SCTP=132,
    
    /// <summary>
    /// Lightweight User Datagram Protocol
    /// RFC 3828
    /// </summary>
    UDPLite=136,
    
    /// <summary>
    /// (VPN) Multiprotocol Label Switching Encapsulated in IP
    /// RFC 4023, RFC 5332
    /// </summary>
    MPLS_in_IP=137,
    
    /// <summary>
    /// (VPN) Wrapped Encapsulating Security Payload
    /// RFC 5840
    /// </summary>
    WESP=141,
    
    // 144-252 are unassigned at this time
    
    // 253 & 254 are reserved for experimentation and testing (RFC 3692)
    
    /// <summary>
    /// Reserved
    /// </summary>
    Reserved=255
}

/// <summary>
/// Type of ICMP message.
/// See https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages
/// </summary>
public enum IcmpType : byte
{
    /// <summary>
    /// Echo Reply (ping)
    /// </summary>
    EchoReply=0,
    
    // 1 and 2 reserved
    
    /// <summary>
    /// Routing failure. Should set Code.
    /// </summary>
    DestinationUnreachable=3,
    
    /// <summary>
    /// Deprecated congestion control
    /// </summary>
    SourceQuench=4,
    
    /// <summary>
    /// Routing command. Should set Code.
    /// </summary>
    RedirectMessage=5,
    
    // 6 and 7 not used
    
    /// <summary>
    /// Echo Request (ping)
    /// </summary>
    EchoRequest=8,
    
    /// <summary>
    /// Router discovery protocol
    /// </summary>
    RouterAdvertisement=9,
    
    /// <summary>
    /// Router discovery protocol
    /// </summary>
    RouterSolicitation=10,
    
    /// <summary>
    /// TTL expired
    /// </summary>
    TimeExceeded=11,
    
    /// <summary>
    /// Parameter Problem. Should set Code.
    /// </summary>
    BadIpHeader=12,
    
    TimestampRequest=13,
    TimestampReply=14,
    
    // 15 to 41 are deprecated or experimental
    
    /// <summary>
    /// XPing request.
    /// See https://tools.ietf.org/html/draft-bonica-intarea-eping-04
    /// </summary>
    ExtendedEchoRequest=42,
    
    /// <summary>
    /// Reply to <see cref="ExtendedEchoRequest"/>.
    /// Should set Code.
    /// </summary>
    ExtendedEchoReply=43,
    
    // 44 to 255 are reserved or experimental
    
    /// <summary>
    /// This is part of ICMPv6, not ICMP.
    /// This enum added to help debugging.
    /// </summary>
    Ipv6EchoRequest=128,
    
    /// <summary>
    /// This is part of ICMPv6, not ICMP.
    /// This enum added to help debugging.
    /// </summary>
    Ipv6EchoReply=129,
}
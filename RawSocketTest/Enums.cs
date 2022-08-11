﻿// ReSharper disable InconsistentNaming
// ReSharper disable IdentifierTypo
// ReSharper disable UnusedMember.Global
// ReSharper disable UnusedType.Global

using System.Diagnostics.CodeAnalysis;

namespace RawSocketTest;

// Huge piles of enums are a sign of a bad design...

[Flags]
public enum MessageFlag : byte
{
    NONE = 0x00,
    
    /// <summary>
    /// Entire message after headers is encrypted
    /// using parameters of security association
    /// </summary>
    Encryption = 0x01,
    
    Commit = 0x02,
    Authentication = 0x04,
    
    /// <summary>
    /// This message comes from the session initiator
    /// (otherwise comes from session responder)
    /// </summary>
    Initiator = 0x08,
    
    /// <summary> Not used </summary>
    CanUseHigherVersion = 0x10,
    
    /// <summary>
    /// This message is a reply
    /// (otherwise is a request)
    /// </summary>
    Response = 0x20
}

public enum ExchangeType : byte
{
    IKE_BASE_1 = 1,
    IDENTITY_1 = 2,
    IKE_AUTH_1 = 3,
    IKE_AGGRESIVE_1 = 4,
    INFORMATIONAL_1 = 5,
    TRANSACTION_1 = 6,
    QUICK_1 = 32,
    NEW_GROUP_1 = 33,
    IKE_SA_INIT = 34,
    IKE_AUTH = 35,
    CREATE_CHILD_SA = 36,
    INFORMATIONAL = 37,
    IKE_SESSION_RESUME = 38,
    GSA_AUTH = 39,
    GSA_REGISTRATION = 40,
    GSA_REKEY = 41
}

/// <summary>
/// Payload types from https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-2
/// </summary>
public enum PayloadType : byte
{
    NONE = 0,
    SA_1 = 1,
    PROPOSAL_1 = 2,
    TRANSFORM_1 = 3,
    KE_1 = 4,
    ID_1 = 5,
    CERT_1 = 6,
    CERTREQ_1 = 7,
    HASH_1 = 8,
    SIG_1 = 9,
    NONCE_1 = 10,
    NOTIFY_1 = 11,
    DELETE_1 = 12,
    VENDOR_1 = 13,
    CP_1 = 14,
    SAK_1 = 15,
    SAT_1 = 16,
    KD_1 = 17,
    SEQ_1 = 18,
    POP_1 = 19,
    NATD_1 = 20,
    NATO_1 = 21,
    GAP_1 = 22,
    
    /// <summary> Security association (33) </summary>
    SA = 33,
    
    /// <summary> Key Exchange (34) </summary>
    KE = 34,
    /// <summary> Identification - Initiator (35) </summary>
    IDi = 35,
    /// <summary> Identification - Responder (36) </summary>
    IDr = 36,
    CERT = 37,
    CERTREQ = 38,
    AUTH = 39,
    NONCE = 40,
    NOTIFY = 41,
    DELETE = 42,
    VENDOR = 43,
    /// <summary> Traffic Selector - Initiator (44) </summary>
    TSi = 44,
    /// <summary> Traffic Selector - Responder (45) </summary>
    TSr = 45,
    /// <summary>
    /// Secured and encrypted (46)
    /// <para></para>
    /// This MUST be the last payload in a message. It SHOULD be the only one.
    /// The body of this payload is encrypted, and will normally represent
    /// multiple child payloads.
    /// </summary>
    SK = 46,
    CP = 47,
    /// <summary> Extensible Authentication (48) </summary>
    EAP = 48,
    GSPM = 49,
    IDg = 50,
    GSA = 51,
    KD = 52,
    SKF = 53,
    PS = 54
}

public enum IkeProtocolType : byte
{
    /// <summary> 0: Out of band (errors) </summary>
    NONE = 0,
    /// <summary> 1: Key exchange. Used to start a Security Association (SA) for use with ESP/AH </summary>
    IKE = 1,
    /// <summary> 2: Authentication Header. Rarely used. </summary>
    AH = 2,
    /// <summary> 3: Encapsulating Security Payload. Provides Data Integrity, Encryption, Authentication, and Anti-Replay functions. </summary>
    ESP = 3,
    FC_ESP_HEADER = 4,
    FC_CT_AUTHENTICATION = 5
}

public enum IkeVersion : byte
{
    /// <summary>
    /// Version 1.0 -- not supported
    /// </summary>
    IkeV1 = 0x10,
    
    /// <summary>
    /// Version 2.0
    /// </summary>
    IkeV2 = 0x20
}

public enum TransformType : byte
{
    ENCR = 1,
    PRF = 2,
    INTEG = 3,
    DH = 4,
    ESN = 5
}

public enum EncryptionTypeId : ushort
{
    ENCR_DES = 2,
    ENCR_3DES = 3,
    ENCR_RC5 = 4,
    ENCR_IDEA = 5,
    ENCR_CAST = 6,
    ENCR_BLOWFISH = 7,
    ENCR_3IDEA = 8,
    ENCR_DES_IV32 = 9,
    ENCR_NULL = 11,
    ENCR_AES_CBC = 12,
    ENCR_AES_CTR = 13,
    ENCR_AES_CCM_8 = 14,
    ENCR_AES_CCM_12 = 15,
    ENCR_AES_CCM_16 = 16,
    ENCR_AES_GCM_8 = 18,
    ENCR_AES_GCM_12 = 19,
    ENCR_AES_GCM_16 = 20,
    ENCR_NULL_AUTH_AES_GMAC = 21,
    ENCR_CAMELLIA_CBC = 23,
    ENCR_CAMELLIA_CTR = 24,
    ENCR_CAMELLIA_CCM_8 = 25,
    ENCR_CAMELLIA_CCM_12 = 26,
    ENCR_CAMELLIA_CCM_16 = 27,
    ENCR_CHACHA20_POLY1305 = 28,
    ENCR_AES_CCM_8_IIV = 29,
    ENCR_AES_GCM_16_IIV = 30,
    ENCR_CHACHA20_POLY1305_IIV = 31
}

public enum PrfId
{
    PRF_HMAC_MD5 = 1,
    PRF_HMAC_SHA1 = 2,
    PRF_HMAC_TIGER = 3,
    PRF_AES128_XCBC = 4,
    PRF_HMAC_SHA2_256 = 5,
    PRF_HMAC_SHA2_384 = 6,
    PRF_HMAC_SHA2_512 = 7,
    PRF_AES128_CMAC = 8
}

public enum IntegId
{
    AUTH_NONE = 0,
    AUTH_HMAC_MD5_96 = 1,
    AUTH_HMAC_SHA1_96 = 2,
    AUTH_DES_MAC = 3,
    AUTH_KPDK_MD5 = 4,
    AUTH_AES_XCBC_96 = 5,
    AUTH_HMAC_MD5_128 = 6,
    AUTH_HMAC_SHA1_160 = 7,
    AUTH_AES_CMAC_96 = 8,
    AUTH_AES_128_GMAC = 9,
    AUTH_AES_192_GMAC = 10,
    AUTH_AES_256_GMAC = 11,
    AUTH_HMAC_SHA2_256_128 = 12,
    AUTH_HMAC_SHA2_384_192 = 13,
    AUTH_HMAC_SHA2_512_256 = 14
}

[SuppressMessage("ReSharper", "CommentTypo")]
public enum DhId : byte
{
    /// <summary> Invalid value </summary>
    DH_NONE = 0,
    
    /// <summary> MODP_768_BIT </summary>
    DH_1 = 1,
    /// <summary> MODP_1024_BIT </summary>
    DH_2 = 2,
    /// <summary> MODP_1536_BIT </summary>
    DH_5 = 5,
    /// <summary> MODP_2048_BIT - best supported by M-Pesa</summary>
    DH_14 = 14,
    /// <summary> MODP_3072_BIT </summary>
    DH_15 = 15,
    /// <summary> MODP_4096_BIT </summary>
    DH_16 = 16,
    /// <summary> MODP_6144_BIT </summary>
    DH_17 = 17,
    /// <summary> MODP_8192_BIT </summary>
    DH_18 = 18,
    /// <summary> ECP_256_BIT </summary>
    DH_19 = 19,
    /// <summary> ECP_384_BIT </summary>
    DH_20 = 20,
    /// <summary> ECP_521_BIT </summary>
    DH_21 = 21,
    /// <summary> MODP_1024_160 </summary>
    DH_22 = 22,
    /// <summary> MODP_2048_224 </summary>
    DH_23 = 23,
    /// <summary> MODP_2048_256 </summary>
    DH_24 = 24,
    /// <summary> ECP_192_BIT </summary>
    DH_25 = 25,
    /// <summary> ECP_224_BIT </summary>
    DH_26 = 26,
    /// <summary> ECP_224_BP </summary>
    DH_27 = 27,
    /// <summary> ECP_256_BP </summary>
    DH_28 = 28,
    /// <summary> ECP_384_BP </summary>
    DH_29 = 29,
    /// <summary> ECP_512_BP </summary>
    DH_30 = 30,
    
    /// <summary>
    /// CURVE_25519
    /// </summary>
    DH_31 = 31,
    
    /// <summary>
    /// CURVE_448
    /// </summary>
    DH_32 = 32,
    None
}

public enum EsnId
{
    NO_ESN = 0,
    ESN = 1
}

public enum NotifyId
{
    UNSUPPORTED_CRITICAL_PAYLOAD = 1,
    DOI_NOT_SUPPORTED = 2,
    SITUATION_NOT_SUPPORTED = 3,
    INVALID_IKE_SPI = 4,
    INVALID_MAJOR_VERSION = 5,
    INVALID_MINOR_VERSION = 6,
    INVALID_SYNTAX = 7,
    INVALID_FLAGS = 8,
    INVALID_MESSAGE_ID = 9,
    INVALID_PROTOCOL_ID = 10,
    INVALID_SPI = 11,
    INVALID_TRANSFORM_ID = 12,
    ATTRIBUTES_NOT_SUPPORTED = 13,
    NO_PROPOSAL_CHOSEN = 14,
    BAD_PROPOSAL_SYNTAX = 15,
    PAYLOAD_MALFORMED = 16,
    INVALID_KE_PAYLOAD = 17,
    INVALID_ID_INFORMATION = 18,
    INVALID_CERT_ENCODING = 19,
    INVALID_CERTIFICATE = 20,
    CERT_TYPE_UNSUPPORTED = 21,
    INVALID_CERT_AUTHORITY = 22,
    INVALID_HASH_INFORMATION = 23,
    AUTHENTICATION_FAILED = 24,
    INVALID_SIGNATURE = 25,
    ADDRESS_NOTIFICATION = 26,
    NOTIFY_SA_LIFETIME = 27,
    CERTIFICATE_UNAVAILABLE = 28,
    UNSUPPORTED_EXCHANGE_TYPE = 29,
    UNEQUAL_PAYLOAD_LENGTHS = 30,
    SINGLE_PAIR_REQUIRED = 34,
    NO_ADDITIONAL_SAS = 35,
    INTERNAL_ADDRESS_FAILURE = 36,
    FAILED_CP_REQUIRED = 37,
    TS_UNACCEPTABLE = 38,
    INVALID_SELECTORS = 39,
    UNACCEPTABLE_ADDRESSES = 40,
    UNEXPECTED_NAT_DETECTED = 41,
    USE_ASSIGNED_HoA = 42,
    TEMPORARY_FAILURE = 43,
    CHILD_SA_NOT_FOUND = 44,
    INVALID_GROUP_ID = 45,
    AUTHORIZATION_FAILED = 46,
    INITIAL_CONTACT = 16384,
    SET_WINDOW_SIZE = 16385,
    ADDITIONAL_TS_POSSIBLE = 16386,
    IPCOMP_SUPPORTED = 16387,
    NAT_DETECTION_SOURCE_IP = 16388,
    NAT_DETECTION_DESTINATION_IP = 16389,
    COOKIE = 16390,
    USE_TRANSPORT_MODE = 16391,
    HTTP_CERT_LOOKUP_SUPPORTED = 16392,
    REKEY_SA = 16393,
    ESP_TFC_PADDING_NOT_SUPPORTED = 16394,
    NON_FIRST_FRAGMENTS_ALSO = 16395,
    MOBIKE_SUPPORTED = 16396,
    ADDITIONAL_IP4_ADDRESS = 16397,
    ADDITIONAL_IP6_ADDRESS = 16398,
    NO_ADDITIONAL_ADDRESSES = 16399,
    UPDATE_SA_ADDRESSES = 16400,
    COOKIE2 = 16401,
    NO_NATS_ALLOWED = 16402,
    AUTH_LIFETIME = 16403,
    MULTIPLE_AUTH_SUPPORTED = 16404,
    ANOTHER_AUTH_FOLLOWS = 16405,
    REDIRECT_SUPPORTED = 16406,
    REDIRECT = 16407,
    REDIRECTED_FROM = 16408,
    TICKET_LT_OPAQUE = 16409,
    TICKET_REQUEST = 16410,
    TICKET_ACK = 16411,
    TICKET_NACK = 16412,
    TICKET_OPAQUE = 16413,
    LINK_ID = 16414,
    USE_WESP_MODE = 16415,
    ROHC_SUPPORTED = 16416,
    EAP_ONLY_AUTHENTICATION = 16417,
    CHILDLESS_IKEV2_SUPPORTED = 16418,
    QUICK_CRASH_DETECTION = 16419,
    IKEV2_MESSAGE_ID_SYNC_SUPPORTED = 16420,
    IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED = 16421,
    IKEV2_MESSAGE_ID_SYNC = 16422,
    IPSEC_REPLAY_COUNTER_SYNC = 16423,
    SECURE_PASSWORD_METHODS = 16424,
    PSK_PERSIST = 16425,
    PSK_CONFIRM = 16426,
    ERX_SUPPORTED = 16427,
    IFOM_CAPABILITY = 16428,
    SENDER_REQUEST_ID = 16429,
    IKEV2_FRAGMENTATION_SUPPORTED = 16430,
    SIGNATURE_HASH_ALGORITHMS = 16431,
    CLONE_IKE_SA_SUPPORTED = 16432,
    CLONE_IKE_SA = 16433,
    PUZZLE = 16434,
    USE_PPK = 16435,
    PPK_IDENTITY = 16436,
    NO_PPK_AUTH = 16437,
    RESPONDER_LIFETIME = 24576,
    REPLAY_STATUS = 24577,
    INITIAL_CONTACT_1 = 24578,
    ISAKMP_NTYPE_R_U_THERE = 36136,
    ISAKMP_NTYPE_R_U_THERE_ACK = 36137,
    ISAKMP_NTYPE_LOAD_BALANCE = 40501,
    ISAKMP_NTYPE_HEARTBEAT = 40503
}

public enum IdType
{
    ID_IPV4_ADDR = 1,
    ID_FQDN = 2,
    ID_RFC822_ADDR = 3,
    ID_IPV4_ADDR_SUBNET = 4,
    ID_IPV6_ADDR = 5,
    ID_IPV6_ADDR_SUBNET = 6,
    ID_IPV4_ADDR_RANGE = 7,
    ID_IPV6_ADDR_RANGE = 8,
    ID_DER_ASN1_DN = 9,
    ID_DER_ASN1_GN = 10,
    ID_KEY_ID = 11,
    ID_FC_NAME = 12,
    ID_NULL = 13
}

public enum AuthMethod
{
    RSA = 1,
    
    /// <summary>
    /// Pre-Shared Key. Usually stored in /etc/ipsec.secrets
    /// </summary>
    PSK = 2,
    
    DSS = 3,
    ECDSA_SHA_256 = 9,
    ECDSA_SHA_384 = 10,
    ECDSA_SHA_512 = 11,
    GENERIC = 12,
    NULL_AUTH = 13,
    DIGITAL = 14
}

public enum CfgType
{
    CFG_REQUEST = 1,
    CFG_REPLY = 2,
    CFG_SET = 3,
    CFG_ACK = 4
}

public enum CpAttrType
{
    INTERNAL_IP4_ADDRESS = 1,
    INTERNAL_IP4_NETMASK = 2,
    INTERNAL_IP4_DNS = 3,
    INTERNAL_IP4_NBNS = 4,
    INTERNAL_ADDRESS_EXPIRY = 5,
    INTERNAL_IP4_DHCP = 6,
    APPLICATION_VERSION = 7,
    INTERNAL_IP6_ADDRESS = 8,
    INTERNAL_IP6_DNS = 10,
    INTERNAL_IP6_DHCP = 12,
    INTERNAL_IP4_SUBNET = 13,
    SUPPORTED_ATTRIBUTES = 14,
    INTERNAL_IP6_SUBNET = 15,
    MIP6_HOME_PREFIX = 16,
    INTERNAL_IP6_LINK = 17,
    INTERNAL_IP6_PREFIX = 18,
    HOME_AGENT_ADDRESS = 19,
    P_CSCF_IP4_ADDRESS = 20,
    P_CSCF_IP6_ADDRESS = 21,
    FTT_KAT = 22,
    EXTERNAL_SOURCE_IP4_NAT_INFO = 23,
    TIMEOUT_PERIOD_FOR_LIVENESS_CHECK = 24,
    INTERNAL_DNS_DOMAIN = 25,
    INTERNAL_DNSSEC_TA = 26,
    XAUTH_TYPE = 16520,
    XAUTH_USER_NAME = 16521,
    XAUTH_USER_PASSWORD = 16522,
    XAUTH_PASSCODE = 16523,
    XAUTH_MESSAGE = 16524,
    XAUTH_CHALLENGE = 16525,
    XAUTH_DOMAIN = 16526,
    XAUTH_STATUS = 16527,
    UNITY_BANNER = 28672,
    UNITY_SAVE_PASSWD = 28673,
    UNITY_DEF_DOMAIN = 28674,
    UNITY_SPLITDNS_NAME = 28675,
    UNITY_SPLIT_INCLUDE = 28676,
    UNITY_NATT_PORT = 28677,
    UNITY_LOCAL_LAN = 28678,
    UNITY_PFS = 28679,
    UNITY_FW_TYPE = 28680,
    UNITY_BACKUP_SERVERS = 28681,
    UNITY_DDNS_HOSTNAME = 28682,
    CICSO_UNKNOWN_SEEN_ON_IPHONE = 28683
}

public enum TrafficSelectType
{
    TS_IPV4_ADDR_RANGE = 7,
    TS_IPV6_ADDR_RANGE = 8,
    TS_FC_ADDR_RANGE = 9
}

public enum IpProtocol : byte
{
    ANY = 0,
    ICMP = 1,
    IGMP = 2,
    GGP = 3,
    IPV4 = 4,
    TCP = 6,
    UDP = 17,
    RDP = 27,
    IPV6 = 41,
    ESP = 50,
    ICMPV6 = 58,
    MH = 135,
    RAW = 255
}

public enum SessionState
{
    INITIAL = 0,
    SA_SENT = 1,
    ESTABLISHED = 2,
    DELETED = 3,
    KE_SENT = 4,
    HASH_SENT = 5,
    AUTH_SET = 6,
    CONF_SENT = 7,
    CHILD_SA_SENT = 8
}

public enum EapCode
{
    REQUEST = 1,
    RESPONSE = 2,
    SUCCESS = 3,
    FAILURE = 4,
    INITIATE = 5,
    FINISH = 6
}

public enum TransformAttr
{
    ENCR = 1,
    HASH = 2,
    AUTH = 3,
    DH = 4,
    DH_TYPE = 5,
    DH_PRIME = 6,
    GENERATOR_1 = 7,
    GENERATOR_2 = 8,
    CURVE_A = 9,
    CURVE_B = 10,
    LIFETYPE = 11,
    DURATION = 12,
    PRF = 13,
    KEY_LENGTH = 14,
    FIELD_SIZE = 15,
    DH_ORDER = 16
}

public enum EspAttr
{
    LIFE_TYPE = 1,
    DURATION = 2,
    GRP_DESC = 3,
    ENC_MODE = 4,
    AUTH = 5,
    KEY_LENGTH = 6,
    KEY_ROUND = 7,
    COMP_DICT_SIZE = 8,
    COMP_PRIVALG = 9,
    SECCTX = 10,
    ESN = 11,
    AUTH_KEY_LENGTH = 12,
    SIG_ALGORITHM = 13,
    ADDR_PRESERVE = 14,
    SA_DIRECTION = 15
}

public enum EncModeId_1
{
    ANY = 0,
    TUNNEL = 1,
    TRNS = 2,
    UDPTUNNEL_RFC = 3,
    UDPTRNS_RFC = 4,
    UDPTUNNEL_DRAFT = 61443,
    UDPTRNS_DRAFT = 61444
}

public enum IntegId_1
{
    AUTH_NONE = 0,
    AUTH_HMAC_MD5 = 1,
    AUTH_HMAC_SHA1 = 2,
    AUTH_DES_MAC = 3,
    AUTH_KPDK = 4,
    AUTH_HMAC_SHA2_256 = 5,
    AUTH_HMAC_SHA2_384 = 6,
    AUTH_HMAC_SHA2_512 = 7,
    AUTH_HMAC_RIPEMD = 8,
    AUTH_AES_XCBC_MAC = 9,
    AUTH_SIG_RSA = 10,
    AUTH_AES_128_GMAC = 11,
    AUTH_AES_192_GMAC = 12,
    AUTH_AES_256_GMAC = 13
}

public enum EncrId_1
{
    DES_CBC = 1,
    IDEA_CBC = 2,
    BLOWFISH_CBC = 3,
    RC5_R16_B64_CBC = 4,
    _3DES_CBC = 5,
    CAST_CBC = 6,
    AES_CBC = 7,
    CAMELLIA_CBC = 8
}

public enum HashId_1
{
    MD5 = 1,
    SHA = 2,
    TIGER = 3,
    SHA2_256 = 4,
    SHA2_384 = 5,
    SHA2_512 = 6
}

public enum AuthId_1
{
    PSK = 1,
    DSS = 2,
    RSA = 3,
    ENCR_RSA = 4,
    RE_ENCR_RSA = 5,
    ECDSA_SHA_256 = 9,
    ECDSA_SHA_384 = 10,
    ECDSA_SHA_512 = 11,
    XAUTHInitPreShared = 65001,
    XAUTHRespPreShared = 65002,
    XAUTHInitDSS       = 65003,
    XAUTHRespDSS       = 65004,
    XAUTHInitRSA       = 65005,
    XAUTHRespRSA       = 65006,
    XAUTHInitRSAEncryption = 65007,
    XAUTHRespRSAEncryption = 65008,
    XAUTHInitRSARevisedEncryption = 65009,
    XAUTHRespRSARevisedEncryption = 65010
}

public enum L2TPType
{
    SCCRQ = 1,
    SCCRP = 2,
    SCCCN = 3,
    StopCCN = 4,
    HELLO = 6,
    OCRQ = 7,
    OCRP = 8,
    OCCN = 9,
    ICRQ = 10,
    ICRP = 11,
    ICCN = 12,
    CDN = 14,
    WEN = 15,
    SLI = 16
}

public enum L2TPAttr
{
    MsgType = 0,
    RandomVector = 36,
    Result = 1,
    Version = 2,
    FramingCap = 3,
    BearerCap = 4,
    TieBreaker = 5,
    Firmware = 6,
    HostName = 7,
    VendorName = 8,
    TunnelID = 9,
    WindowSize = 10,
    Challenge = 11,
    Response = 13,
    CauseCode = 12,
    SessionID = 14,
    CallSerial = 15,
    MinimumBPS = 16,
    MaximumBPS = 17,
    BearerType = 18,
    FramingType = 19,
    CalledNumber = 21,
    CallingNumber = 22,
    SubAddress = 23,
    ConnectSpeed = 24,
    RxConnectSpeed = 38,
    PhysicalChannel = 25,
    PrivateGroupID = 37,
    SequencingRequired = 39,
    InitialLCP = 26,
    LastSentLCP = 27,
    LastReceivedLCP = 28,
    ProxyAuthenType = 29,
    ProxyAuthenName = 30,
    ProxyAuthenChallenge = 31,
    ProxyAuthenID = 32,
    ProxyAuthenResponse = 33,
    CallErrors = 34,
    ACCM = 35
}
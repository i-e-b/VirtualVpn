using RawSocketTest.Crypto;
using RawSocketTest.Helpers;

// ReSharper disable BuiltInTypeReferenceStyle

namespace RawSocketTest;

public class ChildSa
{
    private readonly byte[] _spiIn;
    private readonly byte[] _spiOut;
    private readonly IkeCrypto _cryptoIn;
    private readonly IkeCrypto _cryptoOut;
    private int _msgId_In;
    private int _msgIdOut;
    private readonly HashSet<int> _msgWin;

    // pvpn/server.py:18
    public ChildSa(byte[] spiIn, byte[] spiOut, IkeCrypto cryptoIn, IkeCrypto cryptoOut)
    {
        _spiIn = spiIn;
        _spiOut = spiOut;
        _cryptoIn = cryptoIn;
        _cryptoOut = cryptoOut;
        
        _msgId_In = 1;
        _msgIdOut = 1;
        _msgWin = new HashSet<int>();
        
        var idx = 0;
        SpiIn = Bit.ReadUInt32(spiIn, ref idx);
    }

    public void IncrementMessageId()
    {
        _msgId_In++;

        while (_msgWin.Contains(_msgId_In))
        {
            _msgWin.Remove(_msgId_In);
            _msgId_In++;
        }
    }

    public UInt32 SpiIn { get; set; }
}
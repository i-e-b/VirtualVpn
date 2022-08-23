using System.Diagnostics;

namespace VirtualVpn.TcpProtocol;

/// <summary>
/// Schedule queue item for sequence data
/// </summary>
internal class TcpTimedSequentialData
{
    public Stopwatch Clock { get; set; }
    public long Sequence { get; set; }
    public TcpSegmentFlags Flags { get; set; }
    
    public TcpTimedSequentialData()
    {
        Clock = new Stopwatch();
        Clock.Start();
    }

}
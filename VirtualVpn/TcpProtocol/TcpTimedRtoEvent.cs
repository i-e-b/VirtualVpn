using System.Diagnostics;

namespace VirtualVpn.TcpProtocol;

/// <summary>
/// Schedule slot for Retransmission Time-Out (RTO)
/// </summary>
internal class TcpTimedRtoEvent
{
    public uint Sequence { get; set; }
    public int Length { get; set; }
    public TcpSegmentFlags Flags { get; set; }
    public Action<TcpTimedRtoEvent>? Action { get; set; }
    public TimeSpan Timeout { get; set; }
    public Stopwatch Timer { get; set; }
    
    private readonly object _lock = new();
    private volatile bool _fired = false;

    public TcpTimedRtoEvent()
    {
        Timer = new Stopwatch();
        Timer.Start();
    }

    /// <summary>
    /// Fire the event action if required.
    /// <p></p>
    /// If the event has already been triggered, or the
    /// timeout has not expired, this does nothing.
    /// </summary>
    public void TriggerIfExpired()
    {
        if (_fired) return; // already done
        lock (_lock)
        {
            if (_fired) return; // already done
            if (Timer.Elapsed < Timeout) return; // not time yet
            
            Action?.Invoke(this);
            
            _fired = true;
        }
    }
}
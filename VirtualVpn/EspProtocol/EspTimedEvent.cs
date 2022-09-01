using System.Diagnostics;

namespace VirtualVpn.EspProtocol;

/// <summary>
/// Schedule slot for Retransmission Time-Out (RTO)
/// </summary>
public class EspTimedEvent
{
    public TimeSpan Timeout { get; set; }
    public Stopwatch Timer { get; set; }

    public Action<EspTimedEvent>? Action { get; set; }

    private readonly object _lock = new();
    private volatile bool _fired;

    public EspTimedEvent(Action<EspTimedEvent> action, TimeSpan timeout)
    {
        _fired = false;
        Action = action;
        Timeout = timeout;
        Timer = new Stopwatch();
        Timer.Start();
    }

    public EspTimedEvent()
    {
        Timer = new Stopwatch();
        Timer.Start();
    }

    /// <summary>
    /// Fire the event action if required.
    /// <p></p>
    /// If the event has already been triggered, or the
    /// timeout has not expired, this does nothing.
    /// <p></p>
    /// Returns true if action fired
    /// </summary>
    public bool TriggerIfExpired()
    {
        if (_fired) return false; // already done
        lock (_lock)
        {
            if (_fired) return false; // already done
            if (Timer.Elapsed < Timeout) return false; // not time yet

            _fired = true; // trigger before calling action, so the action can reset
            Action?.Invoke(this);
            return true;
        }
    }

    /// <summary>
    /// <b>FOR TESTING ONLY</b>
    /// <p></p>
    /// After calling this method, the timer is considered immediately expired.
    /// The event will only trigger once <see cref="TriggerIfExpired"/> is called.
    /// The event will not fire again if it has already fired.
    /// </summary>
    public void ForceSet()
    {
        lock (_lock)
        {
            Timeout = TimeSpan.MinValue;
        }
    }

    /// <summary>
    /// The event will not trigger after calling this method.
    /// Works by setting the 'already called' state without
    /// calling the action
    /// </summary>
    public void Clear()
    {
        lock (_lock)
        {
            _fired = true;
        }
    }

    /// <summary>
    /// Resets the clock and fired flag.
    /// The timer retains its original timeout, but starts
    /// counting from now.
    /// If the event has already triggered, it WILL be able
    /// to trigger again.
    /// </summary>
    public void Reset()
    {
        lock (_lock)
        {
            _fired = false;
            Timer.Restart();
        }
    }
}
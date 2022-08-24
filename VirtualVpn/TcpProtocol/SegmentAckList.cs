using System.Collections;

namespace VirtualVpn.TcpProtocol;

internal class SegmentAckList : IEnumerable<TcpTimedSequentialData>
{
    /// <summary>
    /// Sequence => details
    /// </summary>
    private readonly Dictionary<long, TcpTimedSequentialData> _checkList = new();

    private readonly object _lock = new();

    public int Count
    {
        get
        {
            lock (_lock)
            {
                return _checkList.Count;
            }
        }
    }

    public IEnumerator<TcpTimedSequentialData> GetEnumerator()
    {
        lock (_lock)
        {
            var copy = _checkList.Values.ToList(); // we return a copy, so that 'Remove()' can be called in a `foreach`
            return copy.GetEnumerator();
        }
    }

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    public TcpTimedSequentialData? Peek()
    {
        lock (_lock)
        {
            if (_checkList.Count < 1) return null;
            var least = _checkList.Keys.Min();
            return _checkList[least];
        }
    }

    public void Add(TcpTimedSequentialData item)
    {
        lock (_lock)
        {
            if (_checkList.ContainsKey(item.Sequence)) _checkList[item.Sequence] = item; // update with latest counter
            else _checkList.Add(item.Sequence, item);
        }
    }

    public void Remove(TcpTimedSequentialData data)
    {
        lock (_lock)
        {
            _checkList.Remove(data.Sequence);
        }
    }
}
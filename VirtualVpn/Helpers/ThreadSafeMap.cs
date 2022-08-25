namespace VirtualVpn.Helpers;

/// <summary>
/// Wrapper around dictionary that make inserts cleaner,
/// and provides some thread safety
/// </summary>
public class ThreadSafeMap<TKey, TValue> where TKey : notnull
{
    private readonly object _lock = new();
    private readonly Dictionary<TKey, TValue> _dict;

    public ThreadSafeMap()
    {
        _dict = new Dictionary<TKey, TValue>();
    }

    public List<TKey> Keys
    {
        get {
            lock (_lock)
            {
                return _dict.Keys.ToList();
            }
        }
    }

    public TValue? Remove(TKey key)
    {
        lock (_lock)
        {
            var prev = this[key];
            _dict.Remove(key);
            return prev;
        }
    }

    public TValue? this[TKey key]
    {
        get {
            lock (_lock)
            {
                if (!_dict.ContainsKey(key)) return default;
                return _dict[key];
            }
        }
        set {
            lock (_lock)
            {
                if (value is null) return;
                if (!_dict.ContainsKey(key)) _dict.Add(key, value);
                else _dict[key] = value;
            }
        }
    }
}
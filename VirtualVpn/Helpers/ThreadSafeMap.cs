﻿
namespace VirtualVpn.Helpers;

/// <summary>
/// Wrapper around dictionary that make inserts cleaner,
/// and provides some thread safety
/// </summary>
public class ThreadSafeMap<TKey, TValue> where TKey : notnull
{
    private readonly object _lock = new();
    private readonly Dictionary<TKey, TValue> _dict;

    public int Count
    {
        get {
            lock (_lock)
            {
                return _dict.Count;
            }
        }
    }

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

    public bool ContainsKey(TKey key)
    {
        lock (_lock)
        {
            return _dict.ContainsKey(key);
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            _dict.Clear();
        }
    }

    public void RemoveWhere(Func<TValue, bool> selector)
    {
        lock (_lock)
        {
            var keys = new List<TKey>();

            foreach (var kvp in _dict)
            {
                if (selector(kvp.Value))
                {
                    keys.Add(kvp.Key);
                }
            }

            foreach (var key in keys)
            {
                _dict.Remove(key);
            }
        }
    }
}
using System.Diagnostics.CodeAnalysis;

namespace VirtualVpn.Logging;

[SuppressMessage("ReSharper", "InconsistentNaming")]
[SuppressMessage("ReSharper", "CollectionNeverQueried.Global")]
[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class LokiLogBlock
{
    public LokiLogBlock(LokiLogStream stream)
    {
        streams.Add(stream);
    }

    public List<LokiLogStream> streams { get; set; } = new();
}

[SuppressMessage("ReSharper", "InconsistentNaming")]
[SuppressMessage("ReSharper", "CollectionNeverQueried.Global")]
[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class LokiLogStream
{
    public Dictionary<string, string> stream { get; } = new();
    public List<string[]> values { get; } = new();

    public void AddLine(DateTime date, string line)
    {
        values.Add(new[] { UnixTime(date).ToString(), line });
    }

    private static readonly DateTime _epochStart = new(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    private static long UnixTime(DateTime date) => (date - _epochStart).Ticks * 100;
}
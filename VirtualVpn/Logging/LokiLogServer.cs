using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Headers;
using System.Text;
using SkinnyJson;

namespace VirtualVpn.Logging;

/// <summary>
/// Handles buffering log messages, and sending them out on a timer
/// or by volume.
/// </summary>
internal class LokiLogServer
{
    private static readonly HttpClient _client = new();
    private static readonly object _lock = new();
    private volatile bool _running = true;
    private readonly Queue<PendingLogLine> _logQueue = new();
    private Thread? _logPump;

    private void EnsureLoggingThread()
    {
        lock (_lock)
        {
            if (_logPump is not null && (_logPump.IsAlive || _logPump.IsBackground)) return;
            
            _logPump = new Thread(LoggingThreadCore){IsBackground = true};
            _logPump.Start();
        }
    }

    private void LoggingThreadCore()
    {
        var timer = new Stopwatch();
        timer.Start();
        var backoff = 1;
        
        while (_running)
        {
            // If not configured, clear any logs and wait
            if (string.IsNullOrWhiteSpace(Settings.LokiLogUrl))
            {
                lock (_lock) { _logQueue.Clear(); }
                Thread.Sleep(1000);
                continue;
            }

            Uri logUri;
            try
            {
                logUri = new Uri(Settings.LokiLogUrl, UriKind.Absolute);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Loki log push URI is invalid: {ex}");
                Thread.Sleep(1000);
                continue;
            }

            // If there are NOT many messages to send, and we HAVE logged recently, wait.
            if (timer.Elapsed < TimeSpan.FromSeconds(10)
                && _logQueue.Count < 25)
            {
                Thread.Sleep(100 * backoff);
                if (backoff < 10) backoff++;
                continue;
            }
            
            // if timer reset, but there are no messages, reset the timer and continue to wait
            timer.Restart();
            if (_logQueue.Count < 1) { continue; }
            
            // Reset wait duration, send all waiting messages
            backoff = 1;

            // Read messages and reset queue. Fatal errors would lose logs here.
            PendingLogLine[] messages;
            lock (_lock)
            {
                messages = _logQueue.ToArray();
                _logQueue.Clear();
            }

            // try to send messages in bulk to Loki.
            var ok = false;
            try
            {
                TryPushToLoki(messages, logUri);
                ok = true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unexpected error while pushing logs to Loki: {ex}");
            }

            if (ok) continue;
            
            // if we failed, maybe push back onto queue if it's not full
            lock (_lock)
            {
                var returnSet = messages.Take(1000 - _logQueue.Count);
                foreach (var line in returnSet)
                {
                    _logQueue.Enqueue(line);
                }
            }
        }
    }

    private static void TryPushToLoki(PendingLogLine[] messages, Uri logUri)
    {
        // Build object for Loki
        var stream = new LokiLogStream
        {
            // These values keep the VirtualVPN logs similar to the Docker logs the other services output.
            stream = { { "source", "stderr" }, { "container_name", "virtual_vpn" }, { "host", Settings.LokiLogHost } }
        };

        foreach (var message in messages)
        {
            stream.AddLine(message.Date, message.Message);
        }

        var logLine = new LokiLogBlock(stream);
        var bytes = Encoding.UTF8.GetBytes(Json.Freeze(logLine));

        // Send to the server
        using var request = new HttpRequestMessage();
        using var content = new ByteArrayContent(bytes);

        request.RequestUri = logUri;
        request.Method = HttpMethod.Post;
        request.Content = content;
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

        using var response = _client.Send(request);
        if (!response.IsSuccessStatusCode)
        {
            throw new Exception($"Loki push failed: {(int)response.StatusCode} {response.ReasonPhrase}");
        }
    }

    public void Restart()
    {
        Shutdown();
        EnsureLoggingThread();
    }

    /// <summary>
    /// Flush all waiting logs, then stop writer thread
    /// </summary>
    public void Shutdown()
    {
        lock (_lock)
        {
            _running = false;
            
            if (_logPump is null) return;
            if (!_logPump.Join(10_000))
            {
                Console.WriteLine("Loki log runner thread failed to shut-down");
                PushLogImmediate(level: LogLevel.Error, message: "Loki log runner thread failed to shut-down", time: DateTime.UtcNow);
            }
            else
            {
                PushLogImmediate(level: LogLevel.Error, message: "Loki log runner stopped normally", time: DateTime.UtcNow);
            }
            _logPump = null; // if the old pump is stuck, we will leak threads here.
        }
    }

    private void PushLogImmediate(LogLevel level, string message, DateTime time)
    {
        throw new NotImplementedException();
    }
}

public class PendingLogLine
{
    public DateTime Date { get; set; }
    public string Message { get; set; }="";
}

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
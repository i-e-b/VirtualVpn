using System.Diagnostics;
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


    /// <summary>
    /// Add a log line to the outgoing queue.
    /// It will be sent to Loki in batches.
    /// </summary>
    public void AddLog(LogLevel level, string message)
    {
        try
        {
            lock (_lock)
            {
                _logQueue.Enqueue(new PendingLogLine
                {
                    Date = DateTime.UtcNow,
                    Level = level,
                    Message = message
                });
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to store log line: {ex}");
        }
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
    

    /// <summary>
    /// Start the logger thread
    /// </summary>
    public void Start()
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
        Console.WriteLine("LokiLog thread is up");
        
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
                PushToLoki(messages, logUri);
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

    /// <summary>
    /// Push a block of log messages to Loki in one HTTP call.
    /// </summary>
    private static void PushToLoki(PendingLogLine[] messages, Uri logUri)
    {
        // Build object for Loki
        var stream = new LokiLogStream
        {
            // These values keep the VirtualVPN logs similar to the Docker logs the other services output.
            stream = { { "source", "stdout" }, { "container_name", "virtual_vpn" }, { "host", Settings.LokiLogHost } }
        };

        foreach (var message in messages)
        {
            stream.AddLine(message.Date, $"level={LokiString(message.Level)} {message.Message}");
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

    /// <summary>
    /// log level text that matches general use
    /// </summary>
    private static string LokiString(LogLevel level)
    {
        return level switch
        {
            LogLevel.Critical => "error",
            LogLevel.Error => "error",
            LogLevel.Warning => "warn",
            _ => "info"
        };
    }

    /// <summary>
    /// Push a single log message to Loki without
    /// waiting for log pump thread. This should only
    /// be used for messages in the log system itself.
    /// </summary>
    private void PushLogImmediate(LogLevel level, string message, DateTime time)
    {
        try
        {
            var logUrl = Settings.LokiLogUrl;
            if (string.IsNullOrWhiteSpace(logUrl))
            {
                Console.WriteLine("Can't send message. Loki logging url not configured");
                Console.WriteLine($"{time:yyyy-MM-ddTHH:mm} (utc) level={level.ToString()} {message}");
                return;
            }

            PushToLoki(new[]
            {
                new PendingLogLine
                {
                    Date = time,
                    Level = level,
                    Message = message
                }
            }, new Uri(logUrl, UriKind.Absolute));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to send message to Loki: {ex}");
            Console.WriteLine($"{time:yyyy-MM-ddTHH:mm} (utc) level={level.ToString()} {message}");
        }
    }
}
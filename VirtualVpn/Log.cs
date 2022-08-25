using System.Diagnostics.CodeAnalysis;

namespace VirtualVpn;


[SuppressMessage("ReSharper", "UnusedMember.Global")]
public enum LogLevel
{
    None = 0,
    Error = 1,
    Warning = 2,
    Info = 3,
    Debug = 4,
    
    /// <summary>
    /// Include very verbose messages
    /// </summary>
    Trace = 5,
    
    /// <summary>
    /// Include raw data for debugging crypto
    /// </summary>
    Crypto = 6,
    
    /// <summary>
    /// Output all logs
    /// </summary>
    Everything = 255
}

public static class Log
{
    private static LogLevel _level = LogLevel.Warning;
    public static void SetLevel(LogLevel level)
    {
        Console.WriteLine($"Log level set to {(int)level} ({level.ToString()})");
        _level = level;
    }

    public static void Crypto(string msg)
    {
        if (_level < LogLevel.Crypto) return;
        Console.WriteLine(msg);
    }

    public static void Trace(string msg)
    {
        if (_level < LogLevel.Trace) return;
        
        Console.Write("                       "); // same spacing as timestamp
        Console.WriteLine(msg);
    }
    
    public static void Trace(string msg, Func<string> more)
    {
        if (_level < LogLevel.Trace) return;
        
        Console.Write("                       "); // same spacing as timestamp
        Console.Write(msg);
        Console.WriteLine(more());
    }

    public static void Debug(string msg, Func<IEnumerable<string>>? subLines = null)
    {
        if (_level < LogLevel.Debug) return;
        Timestamp();
        
        Console.WriteLine(msg);
        if (subLines is null) return;
        
        var lines = subLines();
        foreach (var line in lines)
        {
            Console.Write("    ");
            Console.WriteLine(line);
        }
    }
    
    public static void Debug(IEnumerable<string> messages)
    {
        if (_level < LogLevel.Debug) return;
        Timestamp();
        
        foreach (var msg in messages)
        {
            Console.Write(msg);
            Console.Write(" ");
        }

        Console.WriteLine();
    }

    public static void Info(string msg)
    {
        if (_level < LogLevel.Info) return;
        Timestamp();
        
        Console.WriteLine(msg);
    }
    
    public static void Warn(string msg)
    {
        if (_level < LogLevel.Warning) return;
        Timestamp();
        
        Console.WriteLine(msg);
    }
    
    public static void Error(string msg)
    {
        if (_level < LogLevel.Error) return;
        Timestamp();
        
        Console.WriteLine(msg);
    }
    

    public static void Error(string message, Exception ex)
    {
        if (_level < LogLevel.Error) return;
        Timestamp();

        if (_level >= LogLevel.Debug)
        {
            Console.WriteLine(message + ": " + ex); // full trace with debug
        }
        else
        {
            Console.WriteLine(message + ": " + ex.Message); // just the top message if not debug
        }
    }

    /// <summary>
    /// Always writes, regardless of log level
    /// </summary>
    public static void Critical(string msg)
    {
        Timestamp();
        Console.WriteLine();
        Console.WriteLine("##################################################");
        Console.WriteLine(msg);
        Console.WriteLine("##################################################");
        Console.WriteLine();
    }

    private static void Timestamp()
    {
        Console.Write(DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm"));
        Console.Write(" (utc) ");
    }
}
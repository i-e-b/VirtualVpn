using System.Diagnostics.CodeAnalysis;

namespace RawSocketTest;


[SuppressMessage("ReSharper", "UnusedMember.Global")]
public enum LogLevel
{
    None = 0,
    Error = 1,
    Warning = 2,
    Info = 3,
    Debug = 4,
    
    /// <summary>
    /// Include raw data for debugging crypto
    /// </summary>
    Crypto = 5
}

public static class Log
{
    private static LogLevel _level = LogLevel.Warning;
    public static void SetLevel(LogLevel level)
    {
        Console.WriteLine($"Log level set to {(int)level} ({level.ToString()})");
        _level = level;
    }

    public static void Debug(string msg, Func<IEnumerable<string>>? subLines = null)
    {
        if (_level < LogLevel.Debug) return;
        
        Console.WriteLine(msg);
        if (subLines is null) return;
        
        var lines = subLines();
        foreach (var line in lines)
        {
            Console.Write("    ");
            Console.WriteLine(line);
        }
    }


    public static void Crypto(string msg)
    {
        if (_level < LogLevel.Crypto) return;
        Console.WriteLine(msg);
    }
    
    public static void Debug(IEnumerable<string> messages)
    {
        if (_level < LogLevel.Debug) return;
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
        
        Console.WriteLine(msg);
    }
    
    public static void Warn(string msg)
    {
        if (_level < LogLevel.Warning) return;
        
        Console.WriteLine(msg);
    }
    
    public static void Error(string msg)
    {
        if (_level < LogLevel.Error) return;
        
        Console.WriteLine(msg);
    }

    /// <summary>
    /// Always writes, regardless of log level
    /// </summary>
    public static void Critical(string msg)
    {
        Console.WriteLine();
        Console.WriteLine("##################################################");
        Console.WriteLine(msg);
        Console.WriteLine("##################################################");
        Console.WriteLine();
    }
}
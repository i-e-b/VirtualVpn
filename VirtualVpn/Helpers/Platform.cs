namespace VirtualVpn.Helpers;

public class Platform
{
    public enum Kind
    {
        /// <summary> Platform/OS not known </summary>
        Unknown = 0,
        /// <summary> Running some kind of Microsoft Windows </summary>
        Windows = 1,
        /// <summary> Running some kind of Linux OS, including Android </summary>
        Linux = 2,
        /// <summary> Running some kind of Apple OSX derivative, including iOS and MacOS </summary>
        MacOs = 3
    }

    /// <summary>
    /// Detect the current runtime environment
    /// </summary>
    public static Kind Current()
    {
        var winDir = Environment.GetEnvironmentVariable("windir");
        if (!string.IsNullOrEmpty(winDir) && winDir.Contains('\\') && Directory.Exists(winDir))
        {
            return Kind.Windows;
        }

        if (File.Exists(@"/proc/sys/kernel/ostype"))
        {
            var osType = File.ReadAllText(@"/proc/sys/kernel/ostype");
            if (osType.StartsWith("Linux", StringComparison.OrdinalIgnoreCase))
            {
                // Note: Android gets here too
                return Kind.Linux;
            }

            return Kind.Unknown;
        }

        if (File.Exists(@"/System/Library/CoreServices/SystemVersion.plist"))
        {
            // Note: iOS gets here too
            return Kind.MacOs;
        }

        return Kind.Unknown;
    }
}
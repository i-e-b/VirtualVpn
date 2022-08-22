namespace VirtualVpn.Helpers;

public static class EnumExtensions
{
    /// <summary>
    /// returns true only if all the selected flags are set.
    /// Undefined on an enum that is not a positive integer value
    /// </summary>
    public static bool FlagsSet<T>(this T value, T targetFlag) where T:Enum
    {
        var b = (ulong)Convert.ChangeType(targetFlag, TypeCode.UInt64);
        if (b == 0) return false; // protect against accidental match-all
        var a = (ulong)Convert.ChangeType(value, TypeCode.UInt64);
        return (a & b) == b;
    }
    
    /// <summary>
    /// returns true only if all the selected flags are clear.
    /// Undefined on an enum that is not a positive integer value
    /// </summary>
    public static bool FlagsClear<T>(this T value, T targetFlag) where T:Enum
    {
        var a = (ulong)Convert.ChangeType(value, TypeCode.UInt64);
        var b = (ulong)Convert.ChangeType(targetFlag, TypeCode.UInt64);
        return (a & b) == 0;
    }
}
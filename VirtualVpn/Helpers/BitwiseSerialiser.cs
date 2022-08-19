using System.Collections;
using System.ComponentModel;
using System.Reflection;
using System.Text;

namespace VirtualVpn.Helpers;
// ReSharper disable UnusedMember.Global
// ReSharper disable UnusedAutoPropertyAccessor.Global
// ReSharper disable UnusedType.Global
// ReSharper disable AutoPropertyCanBeMadeGetOnly.Global
// ReSharper disable BuiltInTypeReferenceStyle
// ReSharper disable MemberCanBePrivate.Global

// Silences Rider/Resharper warnings about unused fields
[AttributeUsage(AttributeTargets.All)] public class MeansImplicitUseAttribute : Attribute { }

/// <summary>
/// Marks a class as representing the fields in a byte array.
/// Each FIELD in the marked class will need to have a byte order and position marker,
/// either <see cref="BigEndianAttribute"/> or <see cref="ByteLayoutChildAttribute"/>
/// </summary>
[MeansImplicitUse, AttributeUsage(AttributeTargets.Class)]
public class ByteLayoutAttribute : Attribute
{
}

/// <summary>
/// Marks a field as representing a subset of fields in a byte array.
/// The child value should be marked with <see cref="ByteLayoutAttribute"/>
/// </summary>
[MeansImplicitUse, AttributeUsage(AttributeTargets.Field)]
public class ByteLayoutChildAttribute : Attribute
{
    public int Order { get; set; }

    /// <summary>
    /// Represents a subset of byte field data.
    /// </summary>
    /// <param name="order">The order through the byte array in which this subset should be processed</param>
    public ByteLayoutChildAttribute(int order)
    {
        Order = order;
    }
}

/// <summary>
/// Indicates that a byte value field should always have a fixed value
/// </summary>
[MeansImplicitUse, AttributeUsage(AttributeTargets.Field)]
public class FixedValueAttribute : Attribute
{
    public byte[] Value { get; set; }

    /// <summary>
    /// Indicates that a byte value field should always have a fixed value
    /// </summary>
    public FixedValueAttribute(params byte[] value)
    {
        Value = value;
    }
}

/// <summary>
/// Represents an unsigned integer value, taking the
/// given number of bytes (1..8), MSB first.
/// Can handle non standard byte counts (e.g. 3 bytes into a UInt32)
/// </summary>
[MeansImplicitUse, AttributeUsage(AttributeTargets.Field)]
public class BigEndianAttribute : Attribute
{
    public int Bytes { get; set; }
    public int Order { get; set; }

    /// <summary>
    /// Represents an unsigned integer value, taking the
    /// given number of bytes (1..8), MSB first.
    /// Can handle non standard byte counts (e.g. 3 bytes into a UInt32)
    /// </summary>
    /// <param name="bytes">Number of bytes in this value. Can be any number from 1 to 8 inclusive.</param>
    /// <param name="order">The order through the byte array in which this value should be processed</param>
    public BigEndianAttribute(int bytes, int order)
    {
        Bytes = bytes;
        Order = order;
    }

    /// <summary>
    /// List of field types that BigEndian can be validly applied to
    /// </summary>
    public static readonly Type[] AcceptableTypes =
    {
        typeof(byte), typeof(UInt16), typeof(UInt32), typeof(UInt64),
        typeof(Int16), typeof(Int32), typeof(Int64)
    };

    /// <summary>
    /// Returns true if the given type can be used for BigEndian fields
    /// </summary>
    public static bool IsAcceptable(Type? fieldType)
    {
        return AcceptableTypes.Contains(fieldType);
    }
}

/// <summary>
/// Represents an unsigned integer value, taking the
/// given number of BITS (1..64), MSB first.
/// Can handle non standard bit counts (e.g. 13 bits into a UInt16)
/// <para></para>
/// A sequence of BigEndianPartial attributes should line up to a byte boundary.
/// </summary>
[MeansImplicitUse, AttributeUsage(AttributeTargets.Field)]
public class BigEndianPartialAttribute : Attribute
{
    public int Bits { get; set; }
    public int Order { get; set; }

    /// <summary>
    /// Represents an unsigned integer value, taking the
    /// given number of bits (1..64), MSB first.
    /// Can handle non standard bit counts (e.g. 13 bits into a UInt16)
    /// </summary>
    /// <param name="bits">Number of bits in this value. Can be any number from 1 to 64 inclusive.</param>
    /// <param name="order">The order through the byte array in which this value should be processed</param>
    public BigEndianPartialAttribute(int bits, int order)
    {
        Bits = bits;
        Order = order;
    }

    /// <summary>
    /// List of field types that BigEndianPartial can be validly applied to
    /// </summary>
    public static readonly Type[] AcceptableTypes =
    {
        typeof(byte), typeof(UInt16), typeof(UInt32), typeof(UInt64),
        typeof(Int16), typeof(Int32), typeof(Int64)
    };

    /// <summary>
    /// Returns true if the given type can be used for BigEndian fields
    /// </summary>
    public static bool IsAcceptable(Type? fieldType)
    {
        return AcceptableTypes.Contains(fieldType);
    }
}

/// <summary>
/// Represents an unsigned integer value, taking the
/// given number of bytes (1..8), LSB first.
/// Can handle non standard byte counts (e.g. 3 bytes into a UInt32)
/// </summary>
[MeansImplicitUse, AttributeUsage(AttributeTargets.Field)]
public class LittleEndianAttribute : Attribute
{
    public int Bytes { get; set; }
    public int Order { get; set; }

    /// <summary>
    /// Represents an unsigned integer value, taking the
    /// given number of bytes (1..8), LSB first.
    /// Can handle non standard byte counts (e.g. 3 bytes into a UInt32)
    /// </summary>
    /// <param name="bytes">Number of bytes in this value. Can be any number from 1 to 8 inclusive.</param>
    /// <param name="order">The order through the byte array in which this value should be processed</param>
    public LittleEndianAttribute(int bytes, int order)
    {
        Bytes = bytes;
        Order = order;
    }

    /// <summary>
    /// List of field types that BigEndian can be validly applied to
    /// </summary>
    public static readonly Type[] AcceptableTypes =
    {
        typeof(byte), typeof(UInt16), typeof(UInt32), typeof(UInt64),
        typeof(Int16), typeof(Int32), typeof(Int64)
    };

    /// <summary>
    /// Returns true if the given type can be used for BigEndian fields
    /// </summary>
    public static bool IsAcceptable(Type? fieldType)
    {
        return AcceptableTypes.Contains(fieldType);
    }
}

/// <summary>
/// Represents a known-length list of bytes in input order
/// </summary>
[MeansImplicitUse, AttributeUsage(AttributeTargets.Field)]
public class ByteStringAttribute : Attribute
{
    public int Bytes { get; set; }
    public int Order { get; set; }

    /// <summary>
    /// Represents a known-length list of bytes in input order
    /// </summary>
    /// <param name="bytes">Number of bytes in this value</param>
    /// <param name="order">The order through the byte array in which this value should be processed</param>
    public ByteStringAttribute(int bytes, int order)
    {
        Bytes = bytes;
        Order = order;
    }

    /// <summary>
    /// List of field types that BigEndian can be validly applied to
    /// </summary>
    public static readonly Type[] AcceptableTypes = { typeof(byte[]) };

    /// <summary>
    /// Returns true if the given type can be used for BigEndian fields
    /// </summary>
    public static bool IsAcceptable(Type? fieldType)
    {
        return AcceptableTypes.Contains(fieldType);
    }
}

/// <summary>
/// Represents an unknown length list of bytes in input order,
/// from the current position to the end of input.
/// <para></para>
/// This should be the last field by order.
/// During serialisation, this is treated as a normal byte string.
/// </summary>
[MeansImplicitUse, AttributeUsage(AttributeTargets.Field)]
public class RemainingBytesAttribute : Attribute
{
    public int Order { get; set; }

    /// <summary>
    /// Represents a list of bytes in input order, from current position to end of input.
    /// </summary>
    /// <param name="order">The order through the byte array in which this value should be processed. This should be the last field by order</param>
    public RemainingBytesAttribute(int order)
    {
        Order = order;
    }

    /// <summary>
    /// List of field types that BigEndian can be validly applied to
    /// </summary>
    public static readonly Type[] AcceptableTypes = { typeof(byte[]) };

    /// <summary>
    /// Returns true if the given type can be used for BigEndian fields
    /// </summary>
    public static bool IsAcceptable(Type? fieldType)
    {
        return AcceptableTypes.Contains(fieldType);
    }
}

/// <summary>
/// Represents a list of bytes in input order, whose length is
/// generated by a named function of the type.
/// <para></para>
/// The function should be a public instance method that takes
/// no parameters and returns an int.
/// The function is allowed to return zero or negative values,
/// which will be interpreted as empty. The resulting byte array
/// will be non-null and zero length.
/// <para></para>
/// When based on another field, that field MUST be in earlier order than
/// the variable byte string.
/// </summary>
[MeansImplicitUse, AttributeUsage(AttributeTargets.Field)]
public class VariableByteStringAttribute : Attribute
{
    public string Source { get; set; }
    public int Order { get; set; }
        
    public VariableByteStringAttribute(string source, int order)
    {
        Source = source;
        Order = order;
    }

    /// <summary>
    /// List of field types that BigEndian can be validly applied to
    /// </summary>
    public static readonly Type[] AcceptableTypes = { typeof(byte[]) };

    /// <summary>
    /// Returns true if the given type can be used for BigEndian fields
    /// </summary>
    public static bool IsAcceptable(Type? fieldType)
    {
        return AcceptableTypes.Contains(fieldType);
    }
}

/// <summary>
/// Special purpose serialiser for extracting and packing communication details for EWCs
/// </summary>
public static class ByteSerialiser
{
    /// <summary>
    /// De-serialiser won't create variable-sized array items larger than this.
    /// </summary>
    public const int VariableByteStringSafetyLimit = 10240;
        
    /// <summary>
    /// Serialise a [ByteLayout] object to a byte array
    /// </summary>
    /// <param name="source">Object to be serialised</param>
    /// <typeparam name="T">Source type. Must be marked with the [ByteLayout] attribute, and obey the rules of the attribute</typeparam>
    /// <returns>Byte array representation of the source</returns>
    public static byte[] ToBytes<T>(T source)
    {
        // Plan:
        // 1. start an empty list
        // 2. get all BigEndianAttribute fields recursively, ordered appropriately
        // 3. run through each field and pull a value (assign to UInt64 and shift?)
        // 4. return the list.ToArray()
        var output = new ByteWriter();

        SerialiseObjectRecursive(source, output);

        return output.ToArray();
    }

    /// <summary>
    /// Deserialise a byte array into a [ByteLayout] object.
    /// If the byte array is too short to fill the object, a partially complete object is returned.
    /// </summary>
    /// <param name="source">Byte array to be deserialised</param>
    /// <param name="result">New instance of T</param>
    /// <typeparam name="T">Target type. Must be marked with the [ByteLayout] attribute, and obey the rules of the attribute</typeparam>
    /// <returns>True if source was long enough to complete the result, false if too short. Returns true if source is longer than needed.</returns>
    public static bool FromBytes<T>(byte[] source, out T result) where T : new()
    {
        var ok = FromBytes(typeof(T), source, out var obj);
        result = (T)obj;
        return ok;
    }

    /// <summary>
    /// Deserialise a subset of a byte array into a [ByteLayout] object.
    /// If the byte array is too short to fill the object, a partially complete object is returned.
    /// </summary>
    /// <param name="source">Byte array to be deserialised</param>
    /// <param name="length">Maximum bytes to read</param>
    /// <param name="result">New instance of T</param>
    /// <param name="offset">Offset into source to start reading</param>
    /// <typeparam name="T">Target type. Must be marked with the [ByteLayout] attribute, and obey the rules of the attribute</typeparam>
    /// <returns>True if source was long enough to complete the result, false if too short. Returns true if source is longer than needed.</returns>
    public static bool FromBytes<T>(byte[] source, int offset, int length, out T result) where T : new()
    {
        if (length <= 0) length = source.Length - offset;
        var feed = source.Skip(offset).Take(length);
        var ok = FromBytes(typeof(T), feed, out var obj);
        result = (T)obj;
        return ok;
    }


    /// <summary>
    /// Deserialise a byte array into a [ByteLayout] object.
    /// If the byte array is too short to fill the object, a partially complete object is returned.
    /// </summary>
    /// <param name="type">Target type. Must be marked with the [ByteLayout] attribute, and obey the rules of the attribute</param>
    /// <param name="source">Byte array to be deserialised</param>
    /// <param name="result">New instance of T</param>
    /// <returns>True if source was long enough to complete the result, false if too short. Returns true if source is longer than needed.</returns>
    public static bool FromBytes(Type type, IEnumerable<byte> source, out object result)
    {
        // Plan:
        // 1. get all BigEndianAttribute fields recursively, ordered appropriately
        // 2. run through each field and pull a value (increment bytes with shift?)
        // 3. return the result type
        result = Activator.CreateInstance(type) ?? throw new Exception($"Failed to create instance of {type.Name}");
        var feed = new RunOutByteQueue(source);

        RestoreObjectRecursive(feed, result);

        return !feed.WasOverRun;
    }

    private static void SerialiseObjectRecursive(object? source, ByteWriter output)
    {
        if (source is null) return;
        var publicFields = source.GetType()
            .GetFields(BindingFlags.Public | BindingFlags.Instance)
            .Where(NotSpecial)
            .OrderBy(AttributeOrder)
            .ToList();

        foreach (var field in publicFields)
        {
            SerialiseFieldRecursive(source, field, output);
        }
    }

    private static void SerialiseFieldRecursive(object? source, FieldInfo field, ByteWriter output)
    {
        if (source is null) return;

        if (IsBigEnd(field, out var byteCount))
        {
            output.WriteBytesBigEnd(GetValueAsInt(source, field), byteCount);
            return;
        }
            
        if (IsPartialBigEnd(field, out var bitCount))
        {
            var intValues = GetValueAsInt(source, field);
            output.WriteBitsBigEndian(intValues, bitCount);
            return;
        }

        if (IsLittleEnd(field, out byteCount))
        {
            output.WriteBytesLittleEnd(GetValueAsInt(source, field), byteCount);
            return;
        }

        if (IsByteString(field, out byteCount)) // if value is longer than declared, we truncate
        {
            var byteValues = GetValueAsByteArray(source, field);
                
            // If value is shorter than declared, we pad
            var pad = byteCount - byteValues.Length;
            for (int i = 0; i < pad; i++)
            {
                output.Add(0);
            }
                
            var idx = 0;
            for (var i = pad; i < byteCount; i++)
            {
                output.Add(byteValues[idx++]);
            }

            return;
        }
            
        if (IsVariableByteString(field, out _)) // We don't use the calc func during serialisation, just write all bytes
        {
            var byteValues = GetValueAsByteArray(source, field);
            for (var i = 0; i < byteValues.Length; i++)
            {
                output.Add(byteValues[i]);
            }

            return;
        }
            
        if (IsRemainingBytes(field)) // Write all bytes
        {
            var byteValues = GetValueAsByteArray(source, field);
            for (var i = 0; i < byteValues.Length; i++)
            {
                output.Add(byteValues[i]);
            }

            return;
        }

        // otherwise we need to recurse deeper
        var child = field.GetValue(source);
        SerialiseObjectRecursive(child, output);
    }

    private static readonly WeakCache<Type, List<FieldInfo>> _publicFieldCache = new(ReadTypeFields);

    private static List<FieldInfo> ReadTypeFields(Type t)
    {
        return t
            .GetFields(BindingFlags.Public | BindingFlags.Instance)
            .Where(NotSpecial)
            .OrderBy(AttributeOrder)
            .ToList();
    }

    /// <summary>
    /// Skip 'special name' fields -- these are used by C# to back flags enums
    /// </summary>
    private static bool NotSpecial(FieldInfo field)
    {
        return !field.IsSpecialName;
    }

    private static void RestoreObjectRecursive(RunOutByteQueue feed, object output)
    {
        var publicFields = _publicFieldCache.Get(output.GetType());

        foreach (var field in publicFields)
        {
            RestoreFieldRecursive(feed, field, output);
        }
    }

    private static void RestoreFieldRecursive(RunOutByteQueue feed, FieldInfo field, object output)
    {
        if (IsBigEnd(field, out var byteCount))
        {
            var intValue = 0UL;
            for (var i = byteCount - 1; i >= 0; i--)
            {
                var b = feed.NextByte();
                intValue += (UInt64)b << (i * 8);
            }

            CastAndSetField(field, output, intValue);
            return;
        }

        if (IsPartialBigEnd(field, out var bitCount))
        {
            var intValue = 0UL;

            while (bitCount > 8)
            {
                var b = feed.NextByte();
                intValue = (intValue << 8) + b;
                bitCount -= 8;
            }

            if (bitCount > 0)
            {
                var b = feed.NextBits(bitCount);
                intValue <<= bitCount;
                intValue |= b;
            }

            CastAndSetField(field, output, intValue);
            return;
        }

        if (IsLittleEnd(field, out byteCount))
        {
            var intValue = 0UL;
            for (var i = 0; i < byteCount; i++)
            {
                var b = feed.NextByte();
                intValue += (UInt64)b << (i * 8);
            }

            CastAndSetField(field, output, intValue);
            return;
        }

        if (IsByteString(field, out byteCount))
        {
            var byteValues = new byte[byteCount];
            for (var i = 0; i < byteCount; i++)
            {
                byteValues[i] = feed.NextByte();
            }

            CastAndSetField(field, output, byteValues);
            return;
        }
            
        if (IsVariableByteString(field, out var functionName))
        {
            // Try to find public instance method by name, and check it's valid
            var method = field.DeclaringType?.GetMethod(functionName, BindingFlags.Public | BindingFlags.Instance);
            if (method is null) throw new Exception($"No such calculation function '{functionName}' in type {field.DeclaringType?.Name}, as declared by its field {field.Name}");
            var methodParams = method.GetParameters();
            if (methodParams.Length > 0) throw new Exception($"Invalid calculator function: {field.DeclaringType?.Name}.{functionName}({string.Join(", ",methodParams.Select(p=>p.Name))}); Calculator functions should have no parameters");
            if (method.ReturnType != typeof(int)) throw new Exception($"Calculator function {field.DeclaringType?.Name}.{functionName}() returns {method.ReturnType.Name}, but should return 'int'");

            // Call the function to get length
            byteCount = (method.Invoke(output, null) as int?) ?? throw new Exception($"Calculator function {field.DeclaringType?.Name}.{functionName}() returned an unexpected value");
                
            // go fetch bytes
            byte[] byteValues;
            if (byteCount < 1 || byteCount > VariableByteStringSafetyLimit)
            {
                byteValues = Array.Empty<byte>();
            }
            else
            {

                byteValues = new byte[byteCount];
                for (var i = 0; i < byteCount; i++)
                {
                    byteValues[i] = feed.NextByte();
                }
            }

            CastAndSetField(field, output, byteValues);
            return;
        }
            
        if (IsRemainingBytes(field))
        {
            var length = feed.GetRemainingLength();
            var byteValues = new byte[length];
            for (var i = 0; i < length; i++)
            {
                byteValues[i] = feed.NextByte();
            }

            CastAndSetField(field, output, byteValues);
            return;
        }

        // otherwise we need to recurse deeper
        var child = field.GetValue(output)
                    ?? Activator.CreateInstance(field.FieldType)
                    ?? throw new Exception($"Failed to find or create instance of {field.DeclaringType?.Name}.{field.Name}");

        RestoreObjectRecursive(feed, child);
    }

    private static void CastAndSetField(FieldInfo field, object output, ulong intValue)
    {
        var t = field.FieldType;

        /**/
        if (t == typeof(byte)) field.SetValue(output, (byte)intValue);
        else if (t == typeof(UInt16)) field.SetValue(output, (UInt16)intValue);
        else if (t == typeof(UInt32)) field.SetValue(output, (UInt32)intValue);
        else if (t == typeof(UInt64)) field.SetValue(output, intValue);
        else if (t == typeof(Int16)) field.SetValue(output, (Int16)intValue);
        else if (t == typeof(Int32)) field.SetValue(output, (Int32)intValue);
        else if (t == typeof(Int64)) field.SetValue(output, (Int64)intValue);
        else if (t.IsEnum)
        {
            field.SetValue(output, Enum.ToObject(t, intValue));
        }
        else throw new Exception($"Unsupported type '{t.Name}' in {field.DeclaringType?.Name}.{field.Name}");
    }

    private static void CastAndSetField(FieldInfo field, object output, byte[] byteValues)
    {
        var t = field.FieldType;

        /**/
        if (t == typeof(byte[])) field.SetValue(output, byteValues);
        else throw new Exception($"Unsupported type '{t.Name}' in {field.DeclaringType?.Name}.{field.Name}");
    }

    private static ulong GetValueAsInt<T>(T source, FieldInfo field)
    {
        if (source is null) return 0UL;
        var val = field.GetValue(source);
        if (val is null) return 0UL;
        var asInt = Convert.ToUInt64(val);
        return asInt;
    }

    private static byte[] GetValueAsByteArray<T>(T source, FieldInfo field)
    {
        if (source is null) return Array.Empty<byte>();
        var val = field.GetValue(source);
        if (val is null) return Array.Empty<byte>();
        if (val is byte[] arr) return arr;
        return Array.Empty<byte>();
    }

    private static readonly WeakCache<MemberInfo, (bool, int)> _isBigEndCache = new(CalculateIsBigEnd);

    private static bool IsBigEnd(MemberInfo field, out int bytes)
    {
        var (result, size) = _isBigEndCache.Get(field);
        bytes = size;
        return result;
    }

    private static (bool, int) CalculateIsBigEnd(MemberInfo field)
    {
        var match = field.CustomAttributes.FirstOrDefault(a => a.AttributeType == typeof(BigEndianAttribute));
        if (match is null) return (false, 0);
        var byteCount = match.ConstructorArguments[0].Value as int?;
        if (byteCount is null) return (false, 0);
        return (true, byteCount.Value);
    }

    private static readonly WeakCache<MemberInfo, (bool, int)> _isPartialBigEndCache = new(CalculateIsPartialBigEnd);

    private static bool IsPartialBigEnd(MemberInfo field, out int bits)
    {
        var (result, size) = _isPartialBigEndCache.Get(field);
        bits = size;
        return result;
    }

    private static (bool, int) CalculateIsPartialBigEnd(MemberInfo field)
    {
        var match = field.CustomAttributes.FirstOrDefault(a => a.AttributeType == typeof(BigEndianPartialAttribute));
        if (match is null) return (false, 0);
        var bitCount = match.ConstructorArguments[0].Value as int?;
        if (bitCount is null) return (false, 0);
        return (true, bitCount.Value);
    }

    private static readonly WeakCache<MemberInfo, (bool, int)> _isLittleEndCache = new(CalculateIsLittleEnd);

    private static bool IsLittleEnd(MemberInfo field, out int bytes)
    {
        var (result, size) = _isLittleEndCache.Get(field);
        bytes = size;
        return result;
    }

    private static (bool, int) CalculateIsLittleEnd(MemberInfo field)
    {
        var match = field.CustomAttributes.FirstOrDefault(a => a.AttributeType == typeof(LittleEndianAttribute));
        if (match is null) return (false, 0);
        var byteCount = match.ConstructorArguments[0].Value as int?;
        if (byteCount is null) return (false, 0);
        return (true, byteCount.Value);
    }

    private static readonly WeakCache<MemberInfo, (bool, int)> _isByteStringCache = new(CalculateIsByteString);

    private static bool IsByteString(MemberInfo field, out int bytes)
    {
        var (result, size) = _isByteStringCache.Get(field);
        bytes = size;
        return result;
    }

    private static (bool, int) CalculateIsByteString(MemberInfo field)
    {
        var match = field.CustomAttributes.FirstOrDefault(a => a.AttributeType == typeof(ByteStringAttribute));
        if (match is null) return (false, 0);
        var byteCount = match.ConstructorArguments[0].Value as int?;
        if (byteCount is null) return (false, 0);
        return (true, byteCount.Value);
    }
        
        
    private static readonly WeakCache<MemberInfo, (bool, string)> _isVariableByteStringCache = new(CalculateIsVariableByteString);

    private static bool IsVariableByteString(MemberInfo field, out string functionName)
    {
        var (result, name) = _isVariableByteStringCache.Get(field);
        functionName = name;
        return result;
    }

    private static (bool, string) CalculateIsVariableByteString(MemberInfo field)
    {
        var match = field.CustomAttributes.FirstOrDefault(a => a.AttributeType == typeof(VariableByteStringAttribute));
        if (match is null) return (false, "");
        var funcName = match.ConstructorArguments[0].Value as string;
        if (funcName is null) return (false, "");
        return (true, funcName);
    }

    private static readonly WeakCache<MemberInfo, bool> _isRemainingBytesCache = new(CalculateIsRemainingBytes);

    private static bool IsRemainingBytes(MemberInfo field)
    {
        var result = _isRemainingBytesCache.Get(field);
        return result;
    }

    private static bool CalculateIsRemainingBytes(MemberInfo field)
    {
        var match = field.CustomAttributes.FirstOrDefault(a => a.AttributeType == typeof(RemainingBytesAttribute));
        if (match is null) return false;
        return true;
    }

    private static readonly WeakCache<FieldInfo, int> _fieldOrderCache = new(CalculateAttributeOrder);

    private static int AttributeOrder(FieldInfo field)
    {
        return _fieldOrderCache.Get(field);
    }

    private static int CalculateAttributeOrder(FieldInfo field)
    {
        var bigEndAttr = field.CustomAttributes.FirstOrDefault(a => a.AttributeType == typeof(BigEndianAttribute))?.ConstructorArguments;
        if (bigEndAttr is not null && bigEndAttr.Count == 2)
        {
            return bigEndAttr[1].Value as int? ?? throw new Exception($"Invalid {nameof(BigEndianAttribute)} definition on {field.DeclaringType?.Name}.{field.Name}");
        }

        var bigEndPartAttr = field.CustomAttributes.FirstOrDefault(a => a.AttributeType == typeof(BigEndianPartialAttribute))?.ConstructorArguments;
        if (bigEndPartAttr is not null && bigEndPartAttr.Count == 2)
        {
            return bigEndPartAttr[1].Value as int? ?? throw new Exception($"Invalid {nameof(BigEndianPartialAttribute)} definition on {field.DeclaringType?.Name}.{field.Name}");
        }

        var littleEndAttr = field.CustomAttributes.FirstOrDefault(a => a.AttributeType == typeof(LittleEndianAttribute))?.ConstructorArguments;
        if (littleEndAttr is not null && littleEndAttr.Count == 2)
        {
            return littleEndAttr[1].Value as int? ?? throw new Exception($"Invalid {nameof(LittleEndianAttribute)} definition on {field.DeclaringType?.Name}.{field.Name}");
        }

        var byteStrAttr = field.CustomAttributes.FirstOrDefault(a => a.AttributeType == typeof(ByteStringAttribute))?.ConstructorArguments;
        if (byteStrAttr is not null && byteStrAttr.Count == 2)
        {
            return byteStrAttr[1].Value as int? ?? throw new Exception($"Invalid {nameof(ByteStringAttribute)} definition on {field.DeclaringType?.Name}.{field.Name}");
        }

        var varByteStrAttr = field.CustomAttributes.FirstOrDefault(a => a.AttributeType == typeof(VariableByteStringAttribute))?.ConstructorArguments;
        if (varByteStrAttr is not null && varByteStrAttr.Count == 2)
        {
            return varByteStrAttr[1].Value as int? ?? throw new Exception($"Invalid {nameof(VariableByteStringAttribute)} definition on {field.DeclaringType?.Name}.{field.Name}");
        }
            
        var remByteAttr = field.CustomAttributes.FirstOrDefault(a => a.AttributeType == typeof(RemainingBytesAttribute))?.ConstructorArguments;
        if (remByteAttr is not null && remByteAttr.Count == 1)
        {
            return remByteAttr[0].Value as int? ?? throw new Exception($"Invalid {nameof(RemainingBytesAttribute)} definition on {field.DeclaringType?.Name}.{field.Name}");
        }

        var childAttr = field.CustomAttributes.FirstOrDefault(a => a.AttributeType == typeof(ByteLayoutChildAttribute))?.ConstructorArguments;
        if (childAttr is not null && childAttr.Count == 1)
        {
            return childAttr[0].Value as int? ?? throw new Exception($"Invalid {nameof(ByteLayoutChildAttribute)} definition on {field.DeclaringType?.Name}.{field.Name}");
        }

        throw new Exception($"No byte layout definition found on {field.DeclaringType?.Name}.{field.Name}");
    }

    internal class RunOutByteQueue
    {
        private readonly Queue<byte> _q;
            
        /// <summary>
        /// Set to 'true' if more bytes were requested than supplied
        /// </summary>
        public bool WasOverRun { get; private set; }

        /// <summary> Last byte we popped when doing `NextBits` </summary>
        private byte _lastFrag;

        /// <summary> Offset in bytes (caused when reading bits). Zero means aligned </summary>
        private int _offset;

        public RunOutByteQueue(IEnumerable<byte> source)
        {
            _q = new Queue<byte>(source);
            _lastFrag = 0;
            _offset=0;
            WasOverRun = false;
        }

        /// <summary>
        /// Read a non-byte aligned number of bits.
        /// Output is in the least-significant bits.
        /// Bit count must be 1..8.
        /// <para></para>
        /// Until `NextBits` is called with a value that
        /// re-aligns the feed, `NextByte` will run slower.
        /// </summary>
        public byte NextBits(int bitCount)
        {
            if (bitCount < 1) return 0;
            if (bitCount > 8) throw new Exception("Byte queue was asked for more than one byte");

            if (_offset == 0) // we are currently aligned
            {
                if (_q.Count < 1) // there is no more data
                {
                    WasOverRun = true;
                    return 0;
                }

                _lastFrag = _q.Dequeue();
            }

            // simple case: there is enough data in the last frag
            int mask, shift;
            byte result;
            var rem = 8 - _offset;

            if (rem >= bitCount)
            {
                // example:
                // offset = 3, bit count = 3
                // 0 1 2 3 4 5 6 7
                // x x x ? ? ? _ _
                // next offset = 6
                // output = (last >> 2) & b00000111

                shift = rem - bitCount;
                mask = (1 << bitCount) - 1;
                result = (byte)((_lastFrag >> shift) & mask);
                _offset = (_offset + bitCount) % 8;
                return result;
            }

            // complex case: we need to mix data from two bytes

            // example:
            // offset = 3, bitCount = 7 => rem = 5, bitsFromNext = 2
            //
            // Input state:
            // 0 1 2 3 4 5 6 7 | 0 1 2 3 4 5 6 7
            // x x x A B C D E | F G _ _ _ _ _ _
            //
            // Output state:
            //     0 1 2 3 4 5 6 7
            // --> _ A B C D E F G 
            //
            // next offset = 2
            // output = ((last & b0001_1111) << 2) | ((next >> 6))
            if (_q.Count < 1) WasOverRun = true;
            var next = (_q.Count > 0) ? _q.Dequeue() : (byte)0;

            mask = (1 << rem) - 1;
            var bitsFromNext = bitCount - rem;
            shift = 8 - bitsFromNext;

            result = (byte)(((_lastFrag & mask) << bitsFromNext) | (next >> shift));

            _lastFrag = next;
            _offset = bitsFromNext;
            return result;
        }

        /// <summary>
        /// Remove a byte from the queue. If there are no bytes
        /// available, a zero value is returned.
        /// </summary>
        public byte NextByte()
        {
            if (_offset != 0) return NextBits(8);
            if (_q.Count > 0) return _q.Dequeue();

            // queue was empty
            WasOverRun = true;
            return 0;
        }

        public int GetRemainingLength() => _q.Count;
    }
}

internal class ByteWriter
{
    private readonly List<byte> _output;
    private int _offset;
    private byte _waiting;

    public ByteWriter()
    {
        _offset = 0;
        _waiting = 0;
        _output = new List<byte>();
    }
        
    public byte[] ToArray()
    {
        // flush last byte?
        if (_offset != 0) _output.Add(_waiting);
            
        // return output
        return _output.ToArray();
    }
        
    public void Add(byte value)
    {
        if (_offset == 0) _output.Add(value);
        else WriteBitsBigEndian(value, 8);
    }

    public void WriteBytesBigEnd(ulong value, int byteCount)
    {
        for (var i = byteCount - 1; i >= 0; i--)
        {
            Add((byte)((value >> (i * 8)) & 0xFF));
        }
    }

    public void WriteBytesLittleEnd(ulong value, int byteCount)
    {
        for (var i = 0; i < byteCount; i++)
        {
            Add((byte)((value >> (i * 8)) & 0xFF));
        }
    }


    /// <summary>
    /// Write a partial byte. While input is not byte aligned,
    /// all writes will be slower
    /// </summary>
    public void WriteBitsBigEndian(ulong value, int bitCount)
    {
        if (bitCount < 1) return;
        if (bitCount > 64) throw new Exception("Invalid bit length in ByteWriter");
            
        var rem = 8 - _offset;
        int shift;
        ulong mask;
            
        // Simple case: will it fit in remaining data of one byte?
        if (bitCount <= rem)
        {
            // example:
            // offset = 3, bit count = 3; value = _ ... _ A B C
            // 0 1 2 3 4 5 6 7
            // x x x A B C _ _
            // next offset = 6
            // _waiting |= (value & b00000111) << 2
                
            shift = rem - bitCount;
            mask = (1ul << bitCount) - 1ul;
            _waiting |= (byte)((value & mask) << shift);
            _offset = (_offset + bitCount) % 8;
            if (_offset == 0)
            {
                _output.Add(_waiting);
                _waiting = 0;
            }
            return;
        }
            
        // Complex case: Data spans multiple bytes
            
        // example 1:
        // offset = 3 (rem = 5), bitCount = 16
        //
        // /-- _waiting --\
        // 0 1 2 3 4 5 6 7 | 0 1 2 3 4 5 6 7 | 0 1 2 3 4 5 6 7
        // x x x A B C D E | F G H I J K L M | N O P _ _ _ _ _
        //
        // bitCount 
        // byte[+0] = ((value & b1111_1xXx__xXxX_xXxX) >> 11)
        // byte[+1] = ((value & b0000_0111__1111_1xXx) >>  3)
        // byte[+2] = ((value & b0000_0000__0000_0111) <<  5)
            
        // example 2:
        // offset = 3 (rem = 5), bitCount = 13
        //
        // /-- _waiting --\
        // 0 1 2 3 4 5 6 7 | 0 1 2 3 4 5 6 7
        // x x x A B C D E | F G H I J K L M
        //
        // bitCount 
        // byte[+0] = ((value & b0001_1111__xXxX_xXxX) >> 8)
        // byte[+1] = ((value & b0000_0000__1111_1111) >>  3)
            
        // first partial
        shift = bitCount - rem;
        mask = (1ul << bitCount) - 1;
        _waiting |= (byte)((value & mask) >> shift);
        _output.Add(_waiting);
        _waiting = 0;
        _offset = 0;
            
        // as many completes as will fit
        while (shift > 0){
            shift -= 8;
            _output.Add((byte)((value >> shift) & 0xff));
        }
            
        // last partial, only if we're going to end un-aligned
        if (shift < 0)
        {
            shift = -shift;
            _offset = 8 - shift;
            _waiting = (byte)((value & 0xff) << shift);
        }
    }
}

public class WeakCache<TK, TV> where TK : notnull
{
    private readonly Func<TK, TV> _generator;
    private readonly Dictionary<TK, TV> _cache = new();

    public WeakCache(Func<TK, TV> generator)
    {
        _generator = generator;
    }

    public TV Get(TK key)
    {
        if (_cache.ContainsKey(key)) return _cache[key];
        var value = _generator(key);
        try
        {
            _cache.Add(key, value);
        }
        catch
        {
            // ignore
        }

        return value;
    }
}

/// <summary>
/// Describes objects, using extra attribute data where available
/// </summary>
public static class TypeDescriber
{
    public static string Describe(object? obj, int indent = 0)
    {
        var sb = new StringBuilder();
        DescribeTypeRecursive(obj, sb, indent);
        return sb.ToString();
    }

    private static void DescribeTypeRecursive(object? obj, StringBuilder sb, int depth)
    {
        if (depth > 10)
        {
            sb.AppendLine("<reached recursion limit>");
            return;
        }

        if (obj is null)
        {
            sb.AppendLine(Indent(depth) + "<null>");
            return;
        }

        if (obj is string str)
        {
            sb.AppendLine(Indent(depth) + $"\"{str}\"");
            return;
        }

        if (obj is byte[] byteString)
        {
            sb.Append(Indent(depth));
            foreach (var b in byteString)
            {
                sb.Append($"{b:X2}");
            }

            sb.AppendLine();
            return;
        }

        if (obj is IEnumerable list && list.GetType() != typeof(char))
        {
            foreach (var item in list)
            {
                DescribeTypeRecursive(item, sb, depth);
            }

            return;
        }

        var publicFields = obj.GetType()
            .GetFields(BindingFlags.Public | BindingFlags.Instance)
            .ToList();

        var publicProps = obj.GetType()
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .ToList();

        foreach (var prop in publicProps)
        {
            if (!prop.CanRead) continue;
            if (IsNullList(prop, obj)) continue; // don't list null lists (we use them for optional messages)
            try
            {
                var value = prop.GetValue(obj);
                sb.Append(Indent(depth) + prop.Name + ": ");

                var description = GetAttributeOfType<DescriptionAttribute>(prop);
                if (description?.Description is not null) sb.Append(description.Description);

                DescribeValue(sb, depth, value);
            }
            catch (TargetParameterCountException ex)
            {
                sb.Append(Indent(depth) + $"Error reading '{prop.Name}': {ex.Message}");
            }
        }

        foreach (var field in publicFields)
        {
            var value = field.GetValue(obj);
            sb.Append($"{Indent(depth)}{field.Name}: ");

            var description = GetAttributeOfType<DescriptionAttribute>(field);
            if (description?.Description is not null) sb.Append(description.Description);

            DescribeValue(sb, depth, value);
        }
    }

    private static bool IsNullList(PropertyInfo prop, object? src)
    {
        if (src is null) return true;
        if (!typeof(IEnumerable).IsAssignableFrom(prop.PropertyType)) return false;
        var value = prop.GetValue(src);
        return value is null;
    }

    private static void DescribeValue(StringBuilder sb, int depth, object? value)
    {
        if (value is null)
        {
            sb.Append("<null>");
        }
        else if (value is string str)
        {
            sb.Append('"');
            sb.Append(str);
            sb.Append('"');
        }
        else if (value is byte[] byteString)
        {
            sb.Append("0x[");
            foreach (var b in byteString)
            {
                sb.Append($"{b:X2}");
            }

            sb.Append("]");
        }
        else if (value is DateTime dt)
        {
            sb.Append(dt.ToString("yyyy-MM-dd HH:mm:ss"));
        }
        else if (value is Enum en)
        {
            var description = GetAttributeOfType<DescriptionAttribute>(en);
            sb.Append(en);
            TryGetEnumHexValue(en, sb);

            if (description?.Description is not null)
            {
                sb.Append(" - ");
                sb.Append(description.Description);
            }
        }
        else if (value is byte b)
        {
            sb.Append($"0x{b:X2} ({b})");
        }
        else if (value is ushort u16)
        {
            sb.Append($"0x{u16:X4} ({u16})");
        }
        else if (value is uint u32)
        {
            sb.Append($"0x{u32:X8} ({u32})");
        }
        else if (value is ulong u64)
        {
            sb.Append($"0x{u64:X16} ({u64})");
        }
        else if (value.GetType().IsPrimitive)
        {
            sb.Append(value.ToString() ?? "<null>?");
        }
        else
        {
            sb.Append("(" + NameForType(value.GetType()) + ")");
            sb.AppendLine();
            DescribeTypeRecursive(value, sb, depth + 1);
        }

        sb.AppendLine();
    }

    private static void TryGetEnumHexValue(Enum en, StringBuilder sb)
    {
        // value__
        var raw = en.GetType().GetField("value__")?.GetValue(en);
        if (raw is null) return;
        sb.Append($" ({raw:X2})");
    }

    /// <summary>
    /// Gets an attribute on a field
    /// </summary>
    /// <typeparam name="T">The type of the attribute you want to retrieve</typeparam>
    private static T? GetAttributeOfType<T>(ICustomAttributeProvider field) where T : Attribute
    {
        var attributes = field.GetCustomAttributes(typeof(T), false);
        return (attributes.Length > 0) ? (T?)attributes[0] : null;
    }

    /// <summary>
    /// Gets an attribute on an enum field value
    /// </summary>
    /// <typeparam name="T">The type of the attribute you want to retrieve</typeparam>
    /// <param name="enumVal">The enum value</param>
    /// <returns>The attribute of type T that should exist on the enum value</returns>
    private static T? GetAttributeOfType<T>(Enum enumVal) where T : Attribute
    {
        var type = enumVal.GetType();
        var name = enumVal.ToString();
        var memInfo = type.GetMember(name);
        if (memInfo.Length < 1) return null;
        var attributes = memInfo[0].GetCustomAttributes(typeof(T), false);
        return (attributes.Length > 0) ? (T?)attributes[0] : null;
    }

    private static string NameForType(Type type)
    {
        if (!type.IsConstructedGenericType) return (type.Name);

        var container = type.Name;
        var contents = type.GenericTypeArguments.Select(NameForType);
        return container[..^2] + "<" + string.Join(",", contents) + ">"; // assumes < 10 generic type params
    }

    private static string Indent(int depth) => new(' ', depth * 2);
}
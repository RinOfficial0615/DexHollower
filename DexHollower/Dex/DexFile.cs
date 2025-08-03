using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace DexHollower.Dex;

/// <summary>
/// Represents the header of a DEX file.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct DexHeader
{
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
    public byte[] magic;
    public uint checksum;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
    public byte[] signature;
    public uint file_size;
    public uint header_size;
    public uint endian_tag;
    public uint link_size;
    public uint link_off;
    public uint map_off;
    public uint string_ids_size;
    public uint string_ids_off;
    public uint type_ids_size;
    public uint type_ids_off;
    public uint proto_ids_size;
    public uint proto_ids_off;
    public uint field_ids_size;
    public uint field_ids_off;
    public uint method_ids_size;
    public uint method_ids_off;
    public uint class_defs_size;
    public uint class_defs_off;
    public uint data_size;
    public uint data_off;

    public readonly string MagicString => Encoding.UTF8.GetString(magic);
}

/// <summary>
/// Represents a string ID item.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct DexStringId
{
    public uint string_data_off;
}

/// <summary>
/// Represents a type ID item.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct DexTypeId
{
    public uint descriptor_idx;
}

/// <summary>
/// Represents a prototype ID item.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct DexProtoId
{
    public uint shorty_idx;
    public uint return_type_idx;
    public uint parameters_off;
}

/// <summary>
/// Represents a type list.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct DexTypeList
{
    public uint size;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0)]
    public ushort[] list;
}


/// <summary>
/// Represents a field ID item.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct DexFieldId
{
    public ushort class_idx;
    public ushort type_idx;
    public uint name_idx;
}

/// <summary>
/// Represents a method ID item.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct DexMethodId
{
    public ushort class_idx;
    public ushort proto_idx;
    public uint name_idx;
}

/// <summary>
/// Represents a class definition item.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct DexClassDef
{
    public uint class_idx;
    public uint access_flags;
    public uint superclass_idx;
    public uint interfaces_off;
    public uint source_file_idx;
    public uint annotations_off;
    public uint class_data_off;
    public uint static_values_off;
}




/// <summary>
/// Main class to parse a DEX file.
/// </summary>
public class DexFile
{
    public DexHeader Header { get; private set; }
    public List<string> StringIds { get; private set; } = [];
    public List<DexTypeId> TypeIds { get; private set; } = [];
    public List<string> TypeNames { get; private set; } = [];
    public List<DexProtoId> ProtoIds { get; private set; } = [];
    public List<DexFieldId> FieldIds { get; private set; } = [];
    public List<DexMethodId> MethodIds { get; private set; } = [];
    public List<DexClassDef> ClassDefs { get; private set; } = [];

    /// <summary>
    /// A dictionary mapping a method index to its corresponding code block.
    /// Not all methods have code (e.g., abstract or native methods).
    /// </summary>
    public Dictionary<uint, DexCodeItem> MethodCodes { get; private set; } = [];

    private readonly byte[] _fileBytes;

    [RequiresDynamicCode("Calls DexHollower.Dex.DexFile.ParseDex()")]
    public DexFile(string filePath)
    {
        _fileBytes = File.ReadAllBytes(filePath);
        ParseDex();
    }

    [RequiresDynamicCode("Calls DexHollower.Dex.DexFile.*")]
    private void ParseDex()
    {
        ReadHeader();
        ReadStringIds();
        ReadTypeIds();
        ResolveTypeNames();
        ReadProtoIds();
        ReadFieldIds();
        ReadMethodIds();
        ReadClassDefs();
        ReadClassData();
    }

    [RequiresDynamicCode("Calls System.Runtime.InteropServices.Marshal.PtrToStructure(nint, Type)")]
    private T ReadStruct<T>(int offset) where T : struct
    {
        GCHandle handle = GCHandle.Alloc(_fileBytes, GCHandleType.Pinned);
        try
        {
            IntPtr ptr = (nint)(handle.AddrOfPinnedObject().ToInt64() + offset);
            object? boxed = Marshal.PtrToStructure(ptr, typeof(T));
            if (boxed is T value)
                return value;
            throw new InvalidDataException($"Failed to unbox struct of type {typeof(T).FullName} at offset {offset}.");
        }
        finally
        {
            handle.Free();
        }
    }

    [RequiresDynamicCode("Calls System.Runtime.InteropServices.Marshal.SizeOf(Type)")]
    private T[] ReadStructs<T>(int offset, uint count) where T : struct
    {
        T[] result = new T[count];
        int size = Marshal.SizeOf(typeof(T));
        for (int i = 0; i < count; i++)
        {
            result[i] = ReadStruct<T>(offset + (i * size));
        }
        return result;
    }

    [RequiresDynamicCode("Calls DexHollower.Dex.DexFile.ReadStruct<T>(Int32)")]
    private void ReadHeader()
    {
        Header = ReadStruct<DexHeader>(0);
        if (Header.header_size != Marshal.SizeOf(typeof(DexHeader)))
        {
            throw new InvalidDataException("Invalid DEX header size.");
        }
        if (!Header.MagicString.StartsWith("dex\n"))
        {
            throw new InvalidDataException("Invalid DEX magic number.");
        }
    }

    [RequiresDynamicCode("Calls DexHollower.Dex.DexFile.ReadStructs<T>(Int32, UInt32)")]
    private void ReadStringIds()
    {
        var stringIdItems = ReadStructs<DexStringId>((int)Header.string_ids_off, Header.string_ids_size);
        foreach (var id in stringIdItems)
        {
            StringIds.Add(ReadStringFromDex((int)id.string_data_off));
        }
    }

    private string ReadStringFromDex(int offset)
    {
        // First, read and skip the ULEB128 encoded length
        ReadUleb128(_fileBytes, ref offset);

        int end = offset;
        while (end < _fileBytes.Length && _fileBytes[end] != 0)
        {
            end++;
        }

        return DecodeMutf8(_fileBytes, offset, end - offset);
    }

    // A simple MUTF-8 decoder
    private string DecodeMutf8(byte[] buffer, int offset, int length)
    {
        List<char> chars = new List<char>();
        for (int i = 0; i < length;)
        {
            byte a = buffer[offset + i++];
            if ((a & 0x80) == 0)
            { // 0xxxxxxx
                chars.Add((char)a);
            }
            else if ((a & 0xE0) == 0xC0)
            { // 110xxxxx 10xxxxxx
                byte b = buffer[offset + i++];
                chars.Add((char)(((a & 0x1F) << 6) | (b & 0x3F)));
            }
            else if ((a & 0xF0) == 0xE0)
            { // 1110xxxx 10xxxxxx 10xxxxxx
                byte b = buffer[offset + i++];
                byte c = buffer[offset + i++];
                chars.Add((char)(((a & 0x0F) << 12) | ((b & 0x3F) << 6) | (c & 0x3F)));
            }
        }
        return new string([.. chars]);
    }

    [RequiresDynamicCode("Calls DexHollower.Dex.DexFile.ReadStructs<T>(Int32, UInt32)")]
    private void ReadTypeIds() =>
        TypeIds.AddRange(ReadStructs<DexTypeId>((int)Header.type_ids_off, Header.type_ids_size));

    private void ResolveTypeNames()
    {
        foreach (var typeId in TypeIds)
        {
            TypeNames.Add(StringIds[(int)typeId.descriptor_idx]);
        }
    }

    [RequiresDynamicCode("Calls DexHollower.Dex.DexFile.ReadStructs<T>(Int32, UInt32)")]
    private void ReadProtoIds() =>
        ProtoIds.AddRange(ReadStructs<DexProtoId>((int)Header.proto_ids_off, Header.proto_ids_size));

    [RequiresDynamicCode("Calls DexHollower.Dex.DexFile.ReadStructs<T>(Int32, UInt32)")]
    private void ReadFieldIds() =>
        FieldIds.AddRange(ReadStructs<DexFieldId>((int)Header.field_ids_off, Header.field_ids_size));

    [RequiresDynamicCode("Calls DexHollower.Dex.DexFile.ReadStructs<T>(Int32, UInt32)")]
    private void ReadMethodIds() =>
        MethodIds.AddRange(ReadStructs<DexMethodId>((int)Header.method_ids_off, Header.method_ids_size));

    [RequiresDynamicCode("Calls DexHollower.Dex.DexFile.ReadStructs<T>(Int32, UInt32)")]
    private void ReadClassDefs() =>
        ClassDefs.AddRange(ReadStructs<DexClassDef>((int)Header.class_defs_off, Header.class_defs_size));

    // --- New Methods for Parsing Bytecode ---

    /// <summary>
    /// Reads a ULEB128 (unsigned little-endian base 128) encoded integer.
    /// </summary>
    private static uint ReadUleb128(byte[] buffer, ref int offset)
    {
        uint result = 0;
        int shift = 0;
        byte b;
        do
        {
            b = buffer[offset++];
            result |= (uint)(b & 0x7F) << shift;
            shift += 7;
        } while ((b & 0x80) != 0);
        return result;
    }

    /// <summary>
    /// Iterates through class definitions to find and parse their associated method code.
    /// </summary>
    [RequiresDynamicCode("Calls ReadCodeItem")]
    private void ReadClassData()
    {
        foreach (var classDef in ClassDefs)
        {
            if (classDef.class_data_off == 0) continue;

            int offset = (int)classDef.class_data_off;

            // Read headers from class_data_item
            uint staticFieldsSize = ReadUleb128(_fileBytes, ref offset);
            uint instanceFieldsSize = ReadUleb128(_fileBytes, ref offset);
            uint directMethodsSize = ReadUleb128(_fileBytes, ref offset);
            uint virtualMethodsSize = ReadUleb128(_fileBytes, ref offset);

            // Skip fields, we only care about methods for now
            for (int i = 0; i < staticFieldsSize; i++) { ReadUleb128(_fileBytes, ref offset); ReadUleb128(_fileBytes, ref offset); }
            for (int i = 0; i < instanceFieldsSize; i++) { ReadUleb128(_fileBytes, ref offset); ReadUleb128(_fileBytes, ref offset); }

            // Read direct methods
            uint lastMethodIdx = 0;
            for (int i = 0; i < directMethodsSize; i++)
            {
                lastMethodIdx = ReadMethod(ref offset, lastMethodIdx);
            }

            // Read virtual methods
            lastMethodIdx = 0;
            for (int i = 0; i < virtualMethodsSize; i++)
            {
                lastMethodIdx = ReadMethod(ref offset, lastMethodIdx);
            }
        }
    }

    /// <summary>
    /// Reads an encoded_method item and its corresponding code_item.
    /// </summary>
    [RequiresDynamicCode("Calls ReadCodeItem")]
    private uint ReadMethod(ref int offset, uint lastMethodIdx)
    {
        uint methodIdxDiff = ReadUleb128(_fileBytes, ref offset);
        uint accessFlags = ReadUleb128(_fileBytes, ref offset);
        uint codeOff = ReadUleb128(_fileBytes, ref offset);

        uint currentMethodIdx = lastMethodIdx + methodIdxDiff;

        if (codeOff > 0)
        {
            DexCodeItem? code = ReadCodeItem((int)codeOff);
            if (code != null)
            {
                MethodCodes[currentMethodIdx] = code;
            }
        }
        return currentMethodIdx;
    }

    /// <summary>
    /// Reads a code_item from a given file offset.
    /// </summary>
    [RequiresDynamicCode("Calls ReadStruct")]
    private DexCodeItem? ReadCodeItem(int offset)
    {
        var header = ReadStruct<DexCodeItemHeader>(offset);

        int instructionsOffset = offset + Marshal.SizeOf<DexCodeItemHeader>();

        // The size is given in 16-bit units, so we multiply by 2 for byte size
        int byteSize = (int)header.insns_size * 2;

        if (instructionsOffset + byteSize > _fileBytes.Length)
        {
            throw new InvalidDataException($"Invalid code item at offset {offset}: instructions exceed file bounds.");
        }

        var instructions = new ushort[header.insns_size];
        if (header.insns_size > 0)
        {
            Buffer.BlockCopy(_fileBytes, instructionsOffset, instructions, 0, byteSize);
        }

        return new DexCodeItem((uint)offset, header, instructions);
    }

    /// <summary>
    /// Retrieves the DexCode object for a given method index.
    /// </summary>
    /// <param name="methodIndex">The index of the method in the method_ids list.</param>
    /// <returns>The DexCode object containing the bytecode, or null if the method has no code.</returns>
    public DexCodeItem? GetCodeForMethod(uint methodIndex)
    {
        return MethodCodes.TryGetValue(methodIndex, out var code) ? code : null;
    }

    /// <summary>
    /// Set the DexCode object for a given method index.
    /// </summary>
    /// <param name="methodIndex">The index of the method in the method_ids list.</param>
    /// <param name="code">The DexCode object containing the bytecode.</param>
    public void SetCodeForMethod(uint methodIndex, DexCodeItem code)
    {
        MethodCodes[methodIndex] = code;
    }

    /// <summary>
    /// Writes the (potentially modified) DEX data to a new file.
    /// This will update the byte array with modified instructions and then recalculate
    /// the checksum and signature before saving.
    /// </summary>
    /// <param name="filePath">The path to save the new DEX file.</param>
    public void Save(string filePath)
    {
        // Step 1: Write any modified instructions back into the main byte array
        foreach (var pair in MethodCodes)
        {
            DexCodeItem code = pair.Value;
            int instructionsOffset = (int)code.CodeOffset + Marshal.SizeOf<DexCodeItemHeader>();
            int byteSize = code.Instructions.Length * 2;
            Buffer.BlockCopy(code.Instructions, 0, _fileBytes, instructionsOffset, byteSize);
        }

        // Step 2: Recalculate SHA-1 Signature
        // The signature is calculated on the file contents *except* for the magic, checksum, and signature fields.
        byte[] signatureHash = SHA1.HashData(_fileBytes.AsSpan(32, _fileBytes.Length - 32));
        Buffer.BlockCopy(signatureHash, 0, _fileBytes, 12, signatureHash.Length); // Write signature to offset 12

        // Step 3: Recalculate Adler32 Checksum
        // The checksum is calculated on the file contents *except* for the magic and checksum fields.
        uint adler = Adler32.Compute(_fileBytes, 12, _fileBytes.Length - 12);
        byte[] checksumBytes = BitConverter.GetBytes(adler);
        Buffer.BlockCopy(checksumBytes, 0, _fileBytes, 8, checksumBytes.Length); // Write checksum to offset 8

        // Step 4: Write the modified byte array to the new file
        File.WriteAllBytes(filePath, _fileBytes);
    }

    public override string ToString()
    {
        var sb = new StringBuilder()
            .AppendLine("--- DEX File Summary ---")
            .AppendLine($"Magic: {Header.MagicString.Replace("\n", "\\n")}")
            .AppendLine($"File Size: {Header.file_size} bytes")
            .AppendLine($"String IDs: {Header.string_ids_size}")
            .AppendLine($"Type IDs: {Header.type_ids_size}")
            .AppendLine($"Proto IDs: {Header.proto_ids_size}")
            .AppendLine($"Field IDs: {Header.field_ids_size}")
            .AppendLine($"Method IDs: {Header.method_ids_size}")
            .AppendLine($"Class Defs: {Header.class_defs_size}")
            .AppendLine("------------------------");

        sb.AppendLine("\n--- Strings ---");
        for (int i = 0; i < StringIds.Count; i++)
        {
            sb.AppendLine($"String {i}: {StringIds[i]}");
        }
        sb.AppendLine("-----------------");

        sb.AppendLine("\n--- Types ---");
        for (int i = 0; i < TypeIds.Count; i++)
        {
            sb.AppendLine($"Type {i}: {TypeNames[i]}")
                .AppendLine($"Descriptor Index: {TypeIds[i].descriptor_idx}");
        }
        sb.AppendLine("---------------");

        sb.AppendLine("\n--- Prototypes ---");
        foreach (var proto in ProtoIds)
        {
            sb.AppendLine($"Shorty: {StringIds[(int)proto.shorty_idx]}, Return Type: {TypeNames[(int)proto.return_type_idx]}");
            if (proto.parameters_off != 0xFFFFFFFF)
            {
                sb.AppendLine($"Parameters Offset: {proto.parameters_off}");
            }
        }
        sb.AppendLine("-------------------");

        sb.AppendLine("\n--- Fields ---");
        foreach (var field in FieldIds)
        {
            sb.AppendLine($"Field: {TypeNames[(int)field.class_idx]}.{StringIds[(int)field.name_idx]} : {TypeNames[(int)field.type_idx]}");
        }
        sb.AppendLine("---------------");

        sb.AppendLine("\n--- Methods ---");
        foreach (var method in MethodIds)
        {
            sb.AppendLine($"Method: {TypeNames[(int)method.class_idx]}.{StringIds[(int)method.name_idx]}")
                .AppendLine($"\tProto Index: {method.proto_idx}");
        }
        sb.AppendLine("----------------");

        sb.AppendLine("\n--- Class Definitions ---");
        foreach (var classDef in ClassDefs)
        {
            sb.AppendLine($"Class: {TypeNames[(int)classDef.class_idx]}")
                .AppendLine($"\tSuperclass: {(classDef.superclass_idx != 0xFFFFFFFF ? TypeNames[(int)classDef.superclass_idx] : "<None>")}")
                .AppendLine($"\tSource File: {(classDef.source_file_idx != 0xFFFFFFFF ? StringIds[(int)classDef.source_file_idx] : "<None>")}");
        }
        sb.AppendLine("-------------------------");

        return sb.ToString();
    }
}

/// <summary>
/// Helper class for calculating the Adler-32 checksum.
/// </summary>
internal static class Adler32
{
    private const uint MOD_ADLER = 65521;

    public static uint Compute(byte[] data, int offset, int length)
    {
        uint a = 1, b = 0;
        for (int i = 0; i < length; i++)
        {
            a = (a + data[offset + i]) % MOD_ADLER;
            b = (b + a) % MOD_ADLER;
        }
        return (b << 16) | a;
    }
}
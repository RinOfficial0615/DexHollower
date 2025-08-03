using System.Runtime.InteropServices;
namespace DexHollower.Dex;

/// <summary>
/// Represents the fixed-size header of a code_item in a DEX file.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct DexCodeItemHeader
{
    public ushort registers_size;
    public ushort ins_size;
    public ushort outs_size;
    public ushort tries_size;
    public uint debug_info_off;
    public uint insns_size;
}

/// <summary>
/// Represents the full code_item for a method, including its bytecode.
/// The Instructions array can be modified.
/// </summary>
public class DexCodeItem(uint codeOffset, DexCodeItemHeader header, ushort[] instructions)
{
    /// <summary>
    /// The file offset to the start of this code_item.
    /// </summary>
    public uint CodeOffset { get; } = codeOffset;

    /// <summary>
    /// The fixed-size header of the code item.
    /// </summary>
    public DexCodeItemHeader Header { get; set; } = header;

    /// <summary>
    /// The method's Dalvik bytecode. Each instruction is a 16-bit unit.
    /// </summary>
    public ushort[] Instructions { get; set; } = instructions;
}

# DexHollower

Fill any method code with `NOP`s.  
Generates a modified DEX and an extracted `code_item.bin` (in custom structure, see below).

## Custom Code Item Structure

```c#
struct CustomCodeItem
{
    public uint debug_info_off;
    public uint insns_size;
    public ushort[] insns;
}
```

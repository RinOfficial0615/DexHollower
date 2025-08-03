using DexHollower.Dex;
using Microsoft.Extensions.Logging;
using System.Diagnostics.CodeAnalysis;
using System.Text;

public class Program
{
    private struct CustomCodeItem
    {
        public uint debug_info_off;
        public uint insns_size;
        public ushort[] insns;
    }

    [RequiresDynamicCode("Calls DexHollower.Dex.DexFile(string filePath)")]
    public static void Main(string[] args)
    {
        using ILoggerFactory loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
        ILogger<Program> logger = loggerFactory.CreateLogger<Program>();

        if (args.Length == 0)
        {
            logger.LogError("Usage: DexHollower.exe <path to dex> [class name] [method name] [method shorty]");
            return;
        }

        var dexFile = new DexFile(args[0]);
        logger.LogInformation("DEX loaded successfully!");
        Console.WriteLine(dexFile);
        if (args.Length < 4)
            return;

        int iMethodIndex = -1;
        for (int i = 0; i < dexFile.MethodIds.Count; i++)
        {
            var methodId = dexFile.MethodIds[i];
            var protoId = dexFile.ProtoIds[methodId.proto_idx];

            string className = dexFile.TypeNames[methodId.class_idx];
            string methodName = dexFile.StringIds[(int)methodId.name_idx];
            string shorty = dexFile.StringIds[(int)protoId.shorty_idx];

            logger.LogDebug("Iterate method {Index}: {ClassName}.{MethodName}(){Shorty}", i, className, methodName, shorty);

            if (className == args[1] && methodName == args[2] && shorty == args[3])
            {
                iMethodIndex = i;
                break;
            }
        }

        if (iMethodIndex == -1)
        {
            logger.LogError("Method {ClassName}.{MethodName}(){Shorty} not found!", args[1], args[2], args[3]);
            return;
        }

        var methodIndex = (uint)iMethodIndex;

        DexCodeItem? code = dexFile.GetCodeForMethod(methodIndex);
        if (code == null)
        {
            logger.LogWarning("Method found, but it has no code (it might be abstract or native).");
            return;
        }

        logger.LogInformation("Found code for method index {MethodIndex}. Instruction count: {InstructionCount}", methodIndex, code.Instructions.Length);

        var customCodeItem = new CustomCodeItem
        {
            debug_info_off = code.Header.debug_info_off,
            insns_size = code.Header.insns_size,
            insns = code.Instructions
        };

        byte[] customCodeItemBytes;
        using (var memoryStream = new MemoryStream())
        {
            using (var writer = new BinaryWriter(memoryStream))
            {
                writer.Write(customCodeItem.debug_info_off);
                writer.Write(customCodeItem.insns_size);

                var insnsBytes = new byte[customCodeItem.insns.Length * sizeof(ushort)];
                Buffer.BlockCopy(customCodeItem.insns, 0, insnsBytes, 0, insnsBytes.Length);
                writer.Write(insnsBytes);
            }
            customCodeItemBytes = memoryStream.ToArray();
        }
        File.WriteAllBytes("code_item.bin", customCodeItemBytes);
        logger.LogInformation("Successfully wrote {ByteCount} bytes to code_item.bin", customCodeItemBytes.Length);

        var insnsDump = new StringBuilder();
        for (int i = 0; i < code.Instructions.Length; i++)
        {
            insnsDump
                .Append(code.Instructions[i].ToString("X4"))    
                .Append(' ');
            code.Instructions[i] = 0x0000; // Replace with NOP (0x0000)
        }
        logger.LogInformation("Instructions dump: {InsnsDump}", insnsDump.ToString());

        dexFile.SetCodeForMethod(methodIndex, code);

        dexFile.Save("modified_classes.dex");
        logger.LogInformation("Modified DEX file saved successfully!");
    }
}
using CommandLine;
using DexHollower.DexFile;
using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace DexHollower;

internal class Hollower
{
    private struct CustomCodeItem
    {
        public uint debug_info_off;
        public uint insns_size;
        public ushort[] insns;
    }

    [Conditional("DEBUG")]
    private static void IsDebugCheck(ref bool isDebug)
    {
        isDebug = true;
    }

#pragma warning disable CS8618
    [Verb("hollow", HelpText = "Hollow any DEX and dump code item")]
    public class HollowOptions
    {
        [Option('i', "input", Required = true, HelpText = "Path to the DEX file to be processed.")]
        public string DexFilePath { get; set; }

        [Option("class", Required = true, HelpText = "The full class name to search for (e.g., Lcom/example/MyClass;).")]
        public string ClassName { get; set; }
        [Option("method", Required = true, HelpText = "The method name to search for (e.g., myMethod).")]
        public string MethodName { get; set; }
        [Option("shorty", Required = true, HelpText = "The method shorty descriptor (e.g., \"V\" for a void method with no parameters).")]
        public string MethodShorty { get; set; }

        [Option("output-dex", Required = false, Default = "modified_classes.dex", HelpText = "Path to save the modified DEX file.")]
        public string OutputDexPath { get; set; }
        [Option("output-code-item", Required = false, Default = "code_item.bin", HelpText = "Path to save the dumped code item.")]
        public string OutputCodeItemPath { get; set; }

        [Option('v', "verbose", Default = false, HelpText = "Enable verbose logging.")]
        public bool Verbose { get; set; }
    }
#pragma warning restore CS8618

    [RequiresDynamicCode("Calls DexHollower.DexFile.DexFile.DexFile(String)")]
    public static int Run(HollowOptions opt)
    {
        var logger =
            LoggerFactory.Create(builder => {
                bool isDebug = false;
                IsDebugCheck(ref isDebug);

                var logLevel = (isDebug || opt.Verbose) ? LogLevel.Debug : LogLevel.Information;

                builder
                    .AddConsole()
                    .SetMinimumLevel(logLevel);
            }).CreateLogger<Hollower>();

        var dexFile = new DexFile.DexFile(opt.DexFilePath);
        logger.LogInformation("DEX loaded successfully!");
        //Console.WriteLine(dexFile);

        int iMethodIndex = -1;
        for (int i = 0; i < dexFile.MethodIds.Count; i++)
        {
            var methodId = dexFile.MethodIds[i];
            var protoId = dexFile.ProtoIds[methodId.proto_idx];

            string className = dexFile.TypeNames[methodId.class_idx];
            string methodName = dexFile.StringIds[(int)methodId.name_idx];
            string shorty = dexFile.StringIds[(int)protoId.shorty_idx];

            logger.LogDebug("Iterate method {Index}: {ClassName}.{MethodName}(){Shorty}", i, className, methodName, shorty);

            if (className == opt.ClassName && methodName == opt.MethodName && shorty == opt.MethodShorty)
            {
                iMethodIndex = i;
                break;
            }
        }

        if (iMethodIndex == -1)
        {
            logger.LogError("Method {ClassName}.{MethodName}(){Shorty} not found!", opt.ClassName, opt.MethodName, opt.MethodShorty);
            return 1;
        }

        var methodIndex = (uint)iMethodIndex;

        DexCodeItem? code = dexFile.GetCodeForMethod(methodIndex);
        if (code == null)
        {
            logger.LogWarning("Method found, but it has no code (it might be abstract or native).");
            return 2;
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
        File.WriteAllBytes(opt.OutputCodeItemPath, customCodeItemBytes);
        logger.LogInformation("Successfully wrote {ByteCount} bytes to {OutputCodeItemPath}", customCodeItemBytes.Length, opt.OutputCodeItemPath);

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

        dexFile.Save(opt.OutputDexPath);
        logger.LogInformation("Modified DEX file saved successfully!");

        return 0;
    }
}

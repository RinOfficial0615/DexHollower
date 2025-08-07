using CommandLine;
using Microsoft.Extensions.Logging;
using System.Diagnostics.CodeAnalysis;

namespace DexHollower;

public class Program
{
    

    [Verb("show", HelpText = "Show DEX file information")]
    public struct ShowOptions
    {
        [Option('i', "input", Required = true, HelpText = "Path to the DEX file to be processed.")]
        public string DexFilePath { get; set; }
    }

    [RequiresDynamicCode("Calls DexHollower.DexFile.DexFile.DexFile(String)")]
    private static void ShowDexInfo(ShowOptions opt)
    {
        Console.WriteLine(new DexFile.DexFile(opt.DexFilePath));
    }

    [RequiresDynamicCode("")]
    public static int Main(string[] args)
    {
        try
        {
            return Parser.Default.ParseArguments<ShowOptions, Hollower.HollowOptions>(args)
                .MapResult(
                (ShowOptions opt) => { ShowDexInfo(opt); return 0; },
                (Hollower.HollowOptions opts) => Hollower.Run(opts),
                error => -1);
        }
        catch (Exception ex)
        {
            Console.WriteLine("An unexpected error occurred:");
            Console.WriteLine(ex);
            return -1;
        }
    }
}
using SecurityReview.CorpusTool.Commands;

if (args.Length > 0)
{
    switch (args[0])
    {
        case "scan-smoke":
            return await ScanSmokeCommand.RunAsync(args[1..]);

        case "verify-parser-corpus":
            return await VerifyParserCorpusCommand.RunAsync(args[1..]);
    }
}

Console.WriteLine("Usage: CorpusTool <command> [options]");
Console.WriteLine("  scan-smoke --root <path>");
Console.WriteLine("  verify-parser-corpus --record --root <corpus-dir> --output <manifest.json>");
Console.WriteLine("  verify-parser-corpus --manifest <manifest.json> --output <results.json>");
return 0;

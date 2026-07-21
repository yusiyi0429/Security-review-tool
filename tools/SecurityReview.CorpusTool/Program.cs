using SecurityReview.CorpusTool.Commands;

if (args.Length > 0)
{
    switch (args[0])
    {
        case "scan-smoke":
            return await ScanSmokeCommand.RunAsync(args[1..]);

        case "verify-parser-corpus":
            return await VerifyParserCorpusCommand.RunAsync(args[1..]);

        case "verify-rule-corpus":
            return await VerifyRuleCorpusCommand.RunAsync(args[1..]);

        case "verify-acceptance":
            return await VerifyAcceptanceCommand.RunAsync(args[1..]);
    }
}

Console.WriteLine("Usage: CorpusTool <command> [options]");
Console.WriteLine("  scan-smoke --root <path>");
Console.WriteLine("  verify-parser-corpus --record --root <corpus-dir> --output <manifest.json>");
Console.WriteLine("  verify-parser-corpus --manifest <manifest.json> --output <results.json>");
Console.WriteLine("  verify-rule-corpus --rules <rule-pack.zip> --manifest <manifest.json> --output <results.json>");
Console.WriteLine("  verify-acceptance --manifest <manifest.json> --output <results.json> [--os-capability any|windows]");
return 0;

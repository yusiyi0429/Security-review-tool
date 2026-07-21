using SecurityReview.CorpusTool.Commands;

if (args.Length > 0 && args[0] == "scan-smoke")
{
    return await ScanSmokeCommand.RunAsync(args[1..]);
}

Console.WriteLine("Usage: CorpusTool scan-smoke --root <path>");
return 0;

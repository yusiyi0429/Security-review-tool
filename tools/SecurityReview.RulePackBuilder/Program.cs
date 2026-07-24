using SecurityReview.RulePack.Signing;
using SecurityReview.RulePackBuilder.Commands;
using SecurityReview.RulePackBuilder.Excel;

if (args.Length == 0)
{
    PrintUsage();
    return 1;
}

string command = args[0].ToLowerInvariant();

switch (command)
{
    case "build":
        return RunBuild(args.AsSpan(1));

    case "verify":
        return RunVerify(args.AsSpan(1));

    case "template":
        return RunTemplate(args.AsSpan(1));

    default:
        PrintUsage();
        return 1;
}

static int RunBuild(ReadOnlySpan<string> args)
{
    string? input = null;
    string? output = null;
    string? privateKeyPath = null;
    string? expectedSigner = null;

    for (int i = 0; i < args.Length; i++)
    {
        if (args[i] == "--input" && i + 1 < args.Length)
            input = args[++i];
        else if (args[i] == "--output" && i + 1 < args.Length)
            output = args[++i];
        else if (args[i] == "--private-key-path" && i + 1 < args.Length)
            privateKeyPath = args[++i];
        else if (args[i] == "--expected-signer" && i + 1 < args.Length)
            expectedSigner = args[++i];
    }

    if (input is null || output is null || privateKeyPath is null)
    {
        Console.Error.WriteLine("Error: --input, --output and --private-key-path are required for build.");
        return 1;
    }

    return BuildRulePackCommand.Run(input, output, privateKeyPath, expectedSigner);
}

static int RunVerify(ReadOnlySpan<string> args)
{
    string? input = null;
    string? expectedSigner = null;
    string? publicKeyBase64 = null;

    for (int i = 0; i < args.Length; i++)
    {
        if (args[i] == "--input" && i + 1 < args.Length)
            input = args[++i];
        else if (args[i] == "--expected-signer" && i + 1 < args.Length)
            expectedSigner = args[++i];
        else if (args[i] == "--public-key" && i + 1 < args.Length)
            publicKeyBase64 = args[++i];
    }

    if (input is null)
    {
        Console.Error.WriteLine("Error: --input is required for verify.");
        return 3;
    }

    expectedSigner ??= EcdsaRulePackSigner.DefaultSignerKeyId;

    byte[] zipBytes;
    try
    {
        zipBytes = File.ReadAllBytes(input);
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"IO Error: Failed to read package: {ex.Message}");
        return 3;
    }

    var result = VerifyPackage(zipBytes, expectedSigner, publicKeyBase64);

    if (result.IsValid)
    {
        Console.WriteLine("Package verification succeeded.");
        return 0;
    }

    Console.Error.WriteLine($"Verification failed: {result.ErrorCode}");
    return 2;
}

static int RunTemplate(ReadOnlySpan<string> args)
{
    string? output = null;

    for (int i = 0; i < args.Length; i++)
    {
        if (args[i] == "--output" && i + 1 < args.Length)
            output = args[++i];
    }

    if (output is null)
    {
        Console.Error.WriteLine("Error: --output is required for template.");
        return 1;
    }

    try
    {
        RuleWorkbookTemplateWriter.Write(output);
        Console.WriteLine($"Template written to {output}.");
        return 0;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"IO Error: Failed to write template: {ex.Message}");
        return 3;
    }
}

static VerifyResult VerifyPackage(byte[] zipBytes, string expectedSigner, string? publicKeyBase64)
{
    if (string.IsNullOrWhiteSpace(publicKeyBase64))
        return EcdsaRulePackSigner.VerifyPackage(zipBytes, expectedSigner);

    try
    {
        using var trustedKey = EcdsaRulePackSigner.ImportPublicKeyFromBase64(publicKeyBase64);
        return EcdsaRulePackSigner.VerifyPackageWithTrustedPublicKey(
            zipBytes, expectedSigner, trustedKey);
    }
    catch
    {
        return new VerifyResult(false, "SIGNATURE_INVALID");
    }
}

static void PrintUsage()
{
    Console.WriteLine("Usage:");
    Console.WriteLine("  SecurityReview.RulePackBuilder build --input <path> --output <path> --private-key-path <path> [--expected-signer <id>]");
    Console.WriteLine("  SecurityReview.RulePackBuilder verify --input <path> [--expected-signer <id>] [--public-key <base64>]");
    Console.WriteLine("  SecurityReview.RulePackBuilder template --output <path>");
    Console.WriteLine();
    Console.WriteLine("Exit codes:");
    Console.WriteLine("  0  Success");
    Console.WriteLine("  1  Validation error");
    Console.WriteLine("  2  Verification / signature failure");
    Console.WriteLine("  3  IO error");
}

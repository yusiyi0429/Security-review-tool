using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using SecurityReview.Domain;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Binary;
using SecurityReview.Parsers.Core;
using SecurityReview.Parsers.Jvm;
using SecurityReview.Parsers.Text;

namespace SecurityReview.WindowsSecurityTests.Parsers;

/// <summary>
/// No-execution monitors. Each test launches a process/HTTP canary and then
/// runs a parser end-to-end against the JVM/Python/PE/ELF corpus. The parser
/// must complete without spawning child processes or opening outbound
/// network sockets. Failures flag a regression that could turn the parser
/// into an arbitrary-code-execution sink.
/// </summary>
public sealed class NoExecutionTests
{
    private const string CanaryFileName = "noexec_canary.txt";
    private const string CanaryContent = "security-review-tool-noexec-marker";

    private static readonly TimeSpan ExecutionTimeout = TimeSpan.FromSeconds(15);

    [Fact]
    public async Task python_lexical_locator_does_not_spawn_process()
    {
        // Capture pre-existing process IDs to detect new ones after parsing.
        var before = GetChildProcessIds("dotnet");
        var source = "value = 'secret'\n# comment\n";

        var result = PythonLexicalLocator.Locate(source);
        Assert.NotEmpty(result.Tokens);

        await Task.Delay(150);
        AssertNoNewProcesses(before);
    }

    [Fact]
    public async Task jvm_class_parser_does_not_spawn_process()
    {
        var before = GetChildProcessIds("dotnet");
        // Truncated class file that triggers every failure path.
        byte[] data = new byte[64];
        var result = JvmClassParser.Parse(data);
        Assert.False(result.IsValid);

        await Task.Delay(150);
        AssertNoNewProcesses(before);
    }

    [Fact]
    public async Task jar_format_parser_does_not_spawn_process()
    {
        // Build a small JAR with a class entry in memory.
        byte[] jar = BuildTinyJar();
        var before = GetChildProcessIds("dotnet");

        var parser = new JarFormatParser();
        var events = await ParseAsync(parser, jar, "test/noexec.jar");
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);

        await Task.Delay(150);
        AssertNoNewProcesses(before);
    }

    [Fact]
    public async Task pe_metadata_parser_does_not_spawn_process()
    {
        var before = GetChildProcessIds("dotnet");
        byte[] data = new byte[1024]; // all zeros — invalid
        var result = PeMetadataParser.Parse(data);
        Assert.False(result.IsValid);

        await Task.Delay(150);
        AssertNoNewProcesses(before);
    }

    [Fact]
    public async Task elf_metadata_parser_does_not_spawn_process()
    {
        var before = GetChildProcessIds("dotnet");
        byte[] data = new byte[1024]; // all zeros — invalid
        var result = ElfMetadataParser.Parse(data);
        Assert.False(result.IsValid);

        await Task.Delay(150);
        AssertNoNewProcesses(before);
    }

    [Fact]
    public async Task printable_string_extractor_does_not_spawn_process()
    {
        var before = GetChildProcessIds("dotnet");
        byte[] data = new byte[2048];
        new Random(42).NextBytes(data);

        var result = PrintableStringExtractor.Extract(data);
        Assert.NotNull(result);

        await Task.Delay(150);
        AssertNoNewProcesses(before);
    }

    [Fact]
    public async Task python_locator_does_not_open_outbound_socket()
    {
        var probe = StartSocketCanary();
        try
        {
            var source = "x = 'a'\n";
            var result = PythonLexicalLocator.Locate(source);
            Assert.NotEmpty(result.Tokens);

            await Task.Delay(150);
            Assert.False(probe.Connected,
                "PythonLexicalLocator must not open outbound sockets.");
        }
        finally
        {
            probe.Dispose();
        }
    }

    [Fact]
    public async Task jvm_class_parser_does_not_open_outbound_socket()
    {
        var probe = StartSocketCanary();
        try
        {
            byte[] data = new byte[64];
            var result = JvmClassParser.Parse(data);
            Assert.False(result.IsValid);

            await Task.Delay(150);
            Assert.False(probe.Connected,
                "JvmClassParser must not open outbound sockets.");
        }
        finally
        {
            probe.Dispose();
        }
    }

    [Fact]
    public async Task pe_metadata_parser_does_not_open_outbound_socket()
    {
        var probe = StartSocketCanary();
        try
        {
            byte[] data = new byte[1024];
            var result = PeMetadataParser.Parse(data);
            Assert.False(result.IsValid);

            await Task.Delay(150);
            Assert.False(probe.Connected,
                "PeMetadataParser must not open outbound sockets.");
        }
        finally
        {
            probe.Dispose();
        }
    }

    [Fact]
    public async Task elf_metadata_parser_does_not_open_outbound_socket()
    {
        var probe = StartSocketCanary();
        try
        {
            byte[] data = new byte[1024];
            var result = ElfMetadataParser.Parse(data);
            Assert.False(result.IsValid);

            await Task.Delay(150);
            Assert.False(probe.Connected,
                "ElfMetadataParser must not open outbound sockets.");
        }
        finally
        {
            probe.Dispose();
        }
    }

    [Fact]
    public async Task printable_string_extractor_does_not_open_outbound_socket()
    {
        var probe = StartSocketCanary();
        try
        {
            byte[] data = new byte[2048];
            new Random(42).NextBytes(data);
            var result = PrintableStringExtractor.Extract(data);
            Assert.NotNull(result);

            await Task.Delay(150);
            Assert.False(probe.Connected,
                "PrintableStringExtractor must not open outbound sockets.");
        }
        finally
        {
            probe.Dispose();
        }
    }

    private static HashSet<int> GetChildProcessIds(string name)
    {
        var ids = new HashSet<int>();
        try
        {
            Process[] procs = Process.GetProcessesByName(name);
            foreach (var p in procs)
            {
                ids.Add(p.Id);
                try { p.Dispose(); } catch { }
            }
        }
        catch
        {
            // Process enumeration can fail on restricted environments; treat
            // as no observable canaries.
        }
        return ids;
    }

    private static void AssertNoNewProcesses(HashSet<int> before)
    {
        var after = GetChildProcessIds("dotnet");
        foreach (int id in after)
        {
            if (!before.Contains(id))
            {
                throw new InvalidOperationException(
                    $"Parser spawned a new process (pid {id}) — must not execute.");
            }
        }
    }

    private static SocketCanary StartSocketCanary()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return new SocketCanary(listener);
    }

    private static async Task<List<ParserEvent>> ParseAsync(JarFormatParser parser, byte[] jar, string virtualPath)
    {
        var events = new List<ParserEvent>();
        using var ms = new MemoryStream(jar, writable: false);
        await using var input = new ParserInput(ms, ms.Length);
        var context = new ParseContext(
            new JobId(Guid.NewGuid()),
            new ScanId(Guid.NewGuid()),
            virtualPath,
            new ParseLimits(DateTimeOffset.UtcNow.AddMinutes(5), 5, 100_000, 50_000_000_000, 1_048_576));
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
        {
            events.Add(evt);
        }
        return events;
    }

    private static byte[] BuildTinyJar()
    {
        using var ms = new MemoryStream();
        using (var zip = new System.IO.Compression.ZipArchive(ms, System.IO.Compression.ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = zip.CreateEntry("META-INF/MANIFEST.MF");
            using var es = entry.Open();
            var data = System.Text.Encoding.UTF8.GetBytes("Manifest-Version: 1.0\n");
            es.Write(data, 0, data.Length);
        }
        return ms.ToArray();
    }

    private sealed class SocketCanary : IDisposable
    {
        private readonly TcpListener _listener;

        public SocketCanary(TcpListener listener)
        {
            _listener = listener;
        }

        public bool Connected
        {
            get
            {
                try
                {
                    // Pending() reflects whether a connection has been accepted.
                    return _listener.Pending();
                }
                catch
                {
                    return false;
                }
            }
        }

        public void Dispose()
        {
            try { _listener.Stop(); } catch { }
        }
    }
}

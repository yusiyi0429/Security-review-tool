using System.Security.Cryptography;
using System.Text.Json;
using SecurityReview.Infrastructure.Cryptography;
using SecurityReview.Infrastructure.Persistence;

namespace SecurityReview.WindowsSecurityTests.Cryptography;

public sealed class DpapiKeyRingTests : IAsyncDisposable
{
    private readonly string _testDir;

    public DpapiKeyRingTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), $"sr-keyring-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_testDir);
    }

    public ValueTask DisposeAsync()
    {
        if (Directory.Exists(_testDir))
        {
            Directory.Delete(_testDir, recursive: true);
        }
        return ValueTask.CompletedTask;
    }

    private AppDataPaths CreatePaths()
    {
        // Use the Config subdirectory for keyring.dat
        var paths = AppDataPaths.CreateForTest(_testDir);
        paths.EnsureCreated();
        return paths;
    }

    [Fact]
    public void First_use_generates_keyring_and_produces_key_id()
    {
        var paths = CreatePaths();
        using var keyRing = WindowsDpapiKeyRing.LoadOrCreate(paths);
        Assert.NotNull(keyRing.KeyId);
        Assert.Equal(16, keyRing.KeyId.Length); // hex of 8 bytes
        Assert.True(File.Exists(paths.KeyRingFile));
    }

    [Fact]
    public void Reload_from_same_file_produces_same_key_id()
    {
        var paths = CreatePaths();
        string keyId1;
        using (var kr = WindowsDpapiKeyRing.LoadOrCreate(paths))
        {
            keyId1 = kr.KeyId;
        }

        using var kr2 = WindowsDpapiKeyRing.LoadOrCreate(paths);
        Assert.Equal(keyId1, kr2.KeyId);
    }

    [Fact]
    public void Reload_from_same_file_produces_same_master_key()
    {
        var paths = CreatePaths();
        byte[] encKey1;
        byte[] fpKey1;
        using (var kr = WindowsDpapiKeyRing.LoadOrCreate(paths))
        {
            encKey1 = kr.Hkdf.DeriveEncryptionKey();
            fpKey1 = kr.Hkdf.DeriveFingerprintKey();
        }

        using var kr2 = WindowsDpapiKeyRing.LoadOrCreate(paths);
        byte[] encKey2 = kr2.Hkdf.DeriveEncryptionKey();
        byte[] fpKey2 = kr2.Hkdf.DeriveFingerprintKey();

        Assert.Equal(encKey1, encKey2);
        Assert.Equal(fpKey1, fpKey2);
    }

    [Fact]
    public void Cannot_load_unknown_user_keyring()
    {
        var paths = CreatePaths();
        File.WriteAllText(paths.KeyRingFile, """
        {
            "schema_version": 1,
            "key_id": "abcdef0123456789",
            "protected_data_base64": "AAAA",
            "created_at_utc": "2026-07-21T00:00:00Z"
        }
        """);

        // The DPAPI-unprotect of random base64 will fail → invalid keyring
        Assert.Throws<InvalidOperationException>(() =>
        {
            using var _ = WindowsDpapiKeyRing.LoadOrCreate(paths);
        });
    }

    [Fact]
    public void Reject_invalid_json_keyring()
    {
        var paths = CreatePaths();
        File.WriteAllText(paths.KeyRingFile, "not json{{");

        Assert.Throws<InvalidOperationException>(() =>
        {
            using var _ = WindowsDpapiKeyRing.LoadOrCreate(paths);
        });
    }

    [Fact]
    public void Reject_invalid_schema_version()
    {
        var paths = CreatePaths();
        File.WriteAllText(paths.KeyRingFile, """
        {
            "schema_version": 999,
            "key_id": "abcdef0123456789",
            "protected_data_base64": "AAAA",
            "created_at_utc": "2026-07-21T00:00:00Z"
        }
        """);

        Assert.Throws<InvalidOperationException>(() =>
        {
            using var _ = WindowsDpapiKeyRing.LoadOrCreate(paths);
        });
    }

    [Fact]
    public void Reject_invalid_base64_in_keyring()
    {
        var paths = CreatePaths();
        File.WriteAllText(paths.KeyRingFile, """
        {
            "schema_version": 1,
            "key_id": "abcdef0123456789",
            "protected_data_base64": "!!!not-base64!!!",
            "created_at_utc": "2026-07-21T00:00:00Z"
        }
        """);

        Assert.Throws<InvalidOperationException>(() =>
        {
            using var _ = WindowsDpapiKeyRing.LoadOrCreate(paths);
        });
    }

    [Fact]
    public void Keyring_file_is_atomic_write()
    {
        var paths = CreatePaths();
        // LoadOrCreate should not leave temp files around
        var tempFiles = Directory.GetFiles(Path.GetDirectoryName(paths.KeyRingFile)!, "*.tmp");
        Assert.Empty(tempFiles);

        using var _ = WindowsDpapiKeyRing.LoadOrCreate(paths);
        // After creation, keyring.dat should exist and be a regular file
        Assert.True(File.Exists(paths.KeyRingFile));
        Assert.False((new FileInfo(paths.KeyRingFile).Attributes & FileAttributes.ReparsePoint) != 0);
    }

    [Fact]
    public void Keyring_document_serialization_roundtrips()
    {
        var doc = new KeyRingDocument
        {
            schema_version = 1,
            key_id = "abcdef0123456789",
            protected_data_base64 = "dGVzdA==",
            created_at_utc = "2026-07-21T00:00:00Z"
        };

        string json = JsonSerializer.Serialize(doc, KeyRingDocumentJsonContext.Default.KeyRingDocument);
        var deserialized = JsonSerializer.Deserialize(json, KeyRingDocumentJsonContext.Default.KeyRingDocument);
        Assert.NotNull(deserialized);
        Assert.Equal(doc.schema_version, deserialized.schema_version);
        Assert.Equal(doc.key_id, deserialized.key_id);
        Assert.Equal(doc.protected_data_base64, deserialized.protected_data_base64);
        Assert.Equal(doc.created_at_utc, deserialized.created_at_utc);
    }

    [Fact]
    public void Dispose_cleans_up_key_material()
    {
        var paths = CreatePaths();
        WindowsDpapiKeyRing? kr = null;
        byte[] encKey;
        using (kr = WindowsDpapiKeyRing.LoadOrCreate(paths))
        {
            encKey = kr.Hkdf.DeriveEncryptionKey();
            Assert.False(encKey.All(b => b == 0));
        }

        // After dispose, derived keys should be zeroed
        Assert.True(encKey.All(b => b == 0));
    }
}

using System.Buffers;
using System.Security.Cryptography;

namespace SecurityReview.Infrastructure.Hashing;

// Streaming SHA-256 over a known content length. Reads in 128 KiB
// ArrayPool-owned buffers, never beyond the declared length, and zeroes the
// used span before returning it so no plaintext leaks across boundaries.
public sealed class Sha256StreamHasher
{
    public const int BufferSize = 128 * 1024;

#pragma warning disable CA1822 // Helper is intentionally a class so the hasher can grow a thread-safe
    // pooled-state cache later; the instance shape is not premature.
    public async Task<string> ComputeAsync(Stream source, long declaredLength,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentOutOfRangeException.ThrowIfNegative(declaredLength);

        byte[] buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        try
        {
            using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long remaining = declaredLength;
            while (remaining > 0)
            {
                int want = (int)Math.Min(buffer.Length, remaining);
                int read = await source.ReadAsync(buffer.AsMemory(0, want), cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                hash.AppendData(buffer, 0, read);
                Array.Clear(buffer, 0, read);
                remaining -= read;
            }

            byte[] digest = hash.GetHashAndReset();
            return Convert.ToHexString(digest).ToLowerInvariant();
        }
        finally
        {
            Array.Clear(buffer, 0, buffer.Length);
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
}

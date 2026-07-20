namespace SecurityReview.ParserContracts.Parsing;

public sealed record ParseLimits(DateTimeOffset DeadlineUtc, int MaxDepth,
    int MaxEntriesRemaining, long MaxExpandedBytesRemaining, int MaxChunkBytes)
{
    public IReadOnlyList<string> Validate(DateTimeOffset nowUtc)
    {
        var errors = new List<string>();
        if (DeadlineUtc <= nowUtc) errors.Add("deadline_expired");
        if (MaxDepth is < 0 or > 5) errors.Add("depth_out_of_range");
        if (MaxEntriesRemaining is < 0 or > 100_000) errors.Add("entries_out_of_range");
        if (MaxExpandedBytesRemaining is < 0 or > 53_687_091_200L) errors.Add("expanded_bytes_out_of_range");
        if (MaxChunkBytes is < 1 or > 1_048_576) errors.Add("chunk_bytes_out_of_range");
        return errors;
    }
}

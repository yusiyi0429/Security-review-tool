namespace SecurityReview.Application.Scans.Inventory;

// Bounded mutation action. identical hashes -> Accept. A change on the first
// observation gives the parser one retry (RescanOnce); any further change
// marks the file FileUnstable and produces no resolved finding.
public enum FileStabilityAction
{
    Accept,
    RescanOnce,
    MarkUnstable
}

public static class FileStabilityDecision
{
    public static FileStabilityAction Decide(bool hashesEqual, int priorRetries)
    {
        if (hashesEqual)
        {
            return FileStabilityAction.Accept;
        }

        return priorRetries == 0
            ? FileStabilityAction.RescanOnce
            : FileStabilityAction.MarkUnstable;
    }
}

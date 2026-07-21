namespace SecurityReview.Application.Scans.Inventory;

// Bounded mutation action. Identical hashes with preserved identity -> Accept.
// Content changed (hash differs, identity preserved) -> one retry (RescanOnce);
// a further change -> MarkUnstable. Identity changed (replacement by rename,
// new inode) -> MarkUnstable immediately — the old handle points to a stale inode
// and re-reading gives the same old content.
public enum FileStabilityAction
{
    Accept,
    RescanOnce,
    MarkUnstable
}

public static class FileStabilityDecision
{
    public static FileStabilityAction Decide(bool hashesEqual, int priorRetries, bool identityPreserved = false)
    {
        if (!identityPreserved)
        {
            return FileStabilityAction.MarkUnstable;
        }

        if (hashesEqual)
        {
            return FileStabilityAction.Accept;
        }

        return priorRetries == 0
            ? FileStabilityAction.RescanOnce
            : FileStabilityAction.MarkUnstable;
    }
}

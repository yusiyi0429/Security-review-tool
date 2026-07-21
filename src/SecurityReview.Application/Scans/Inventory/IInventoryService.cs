namespace SecurityReview.Application.Scans.Inventory;

public interface IInventoryService
{
    // Builds the root-bounded inventory. Never throws for access errors (those
    // become typed gaps); an unidentifiable or unenumerable root yields
    // Outcome.RootFailed, never a partial empty inventory.
    Task<InventoryResult> BuildAsync(InventoryRequest request,
        CancellationToken cancellationToken);
}

using System.Collections.ObjectModel;
using System.Windows.Input;
using SecurityReview.Desktop.Services;
using SecurityReview.Domain.Findings;

namespace SecurityReview.Desktop.ViewModels;

/// <summary>
/// View model for the safe preview display.
/// Renders bounded, read-only text/table/binary fragments.
/// Never opens input with shell, Office, PDF, or browser controls.
/// </summary>
public sealed class SafePreviewViewModel : ObservableObject
{
    private readonly SafePreviewService _previewService;

    private string _previewTitle = "";
    private string _locatorInfo = "";
    private string _truncationNote = "";

    // Text preview
    private ObservableCollection<SafePreviewLineItem> _textLines = new();
    private int _highlightLineIndex = -1;
    private int _highlightCharStart;
    private int _highlightCharEnd;
    private bool _isTextPreview;

    // Table preview
    private ObservableCollection<TableRowItem> _tableRows = new();
    private int _highlightTableRow = -1;
    private string _highlightTableCell = "";
    private bool _isTablePreview;

    // Binary preview
    private ObservableCollection<HexLineItem> _hexLines = new();
    private ObservableCollection<string> _textLinesOnly = new();
    private bool _isBinaryPreview;

    private bool _hasContent;

    public SafePreviewViewModel(SafePreviewService previewService)
    {
        _previewService = previewService ?? throw new ArgumentNullException(nameof(previewService));
    }

    // ------------------------------------------------------------------ Properties

    public string PreviewTitle
    {
        get => _previewTitle;
        set => SetProperty(ref _previewTitle, value);
    }

    public string LocatorInfo
    {
        get => _locatorInfo;
        set => SetProperty(ref _locatorInfo, value);
    }

    public string TruncationNote
    {
        get => _truncationNote;
        set => SetProperty(ref _truncationNote, value);
    }

    public ObservableCollection<SafePreviewLineItem> TextLines
    {
        get => _textLines;
        set => SetProperty(ref _textLines, value);
    }

    public int HighlightLineIndex
    {
        get => _highlightLineIndex;
        set => SetProperty(ref _highlightLineIndex, value);
    }

    public int HighlightCharStart
    {
        get => _highlightCharStart;
        set => SetProperty(ref _highlightCharStart, value);
    }

    public int HighlightCharEnd
    {
        get => _highlightCharEnd;
        set => SetProperty(ref _highlightCharEnd, value);
    }

    public bool IsTextPreview
    {
        get => _isTextPreview;
        set => SetProperty(ref _isTextPreview, value);
    }

    public ObservableCollection<TableRowItem> TableRows
    {
        get => _tableRows;
        set => SetProperty(ref _tableRows, value);
    }

    public int HighlightTableRow
    {
        get => _highlightTableRow;
        set => SetProperty(ref _highlightTableRow, value);
    }

    public string HighlightTableCell
    {
        get => _highlightTableCell;
        set => SetProperty(ref _highlightTableCell, value);
    }

    public bool IsTablePreview
    {
        get => _isTablePreview;
        set => SetProperty(ref _isTablePreview, value);
    }

    public ObservableCollection<HexLineItem> HexLines
    {
        get => _hexLines;
        set => SetProperty(ref _hexLines, value);
    }

    public ObservableCollection<string> TextLinesOnly
    {
        get => _textLinesOnly;
        set => SetProperty(ref _textLinesOnly, value);
    }

    public bool IsBinaryPreview
    {
        get => _isBinaryPreview;
        set => SetProperty(ref _isBinaryPreview, value);
    }

    public bool HasContent
    {
        get => _hasContent;
        set => SetProperty(ref _hasContent, value);
    }

    // ------------------------------------------------------------------ Load methods

    public void LoadTextPreview(string fullText, SourceLocator locator, string title)
    {
        ClearCurrentPreview();

        var fragment = SafePreviewService.PreviewText(fullText, locator);

        _textLines.Clear();
        foreach (var line in fragment.Lines)
            _textLines.Add(new SafePreviewLineItem(line.LineNumber, line.Text));

        HighlightLineIndex = fragment.HighlightLineIndex;
        HighlightCharStart = fragment.HighlightCharStart;
        HighlightCharEnd = fragment.HighlightCharEnd;
        LocatorInfo = fragment.LocatorDisplay;

        var truncParts = new List<string>();
        if (fragment.TruncatedBefore > 0) truncParts.Add($"上方省略 {fragment.TruncatedBefore} 行");
        if (fragment.TruncatedAfter > 0) truncParts.Add($"下方省略 {fragment.TruncatedAfter} 行");
        TruncationNote = string.Join("，", truncParts);

        PreviewTitle = title;
        IsTextPreview = true;
        IsTablePreview = false;
        IsBinaryPreview = false;
        HasContent = fragment.Lines.Count > 0;
    }

    public void LoadTablePreview(IReadOnlyList<IReadOnlyList<string>> rows, SourceLocator.CellLocator locator, string title)
    {
        ClearCurrentPreview();

        var preview = SafePreviewService.PreviewTable(rows, locator);

        _tableRows.Clear();
        foreach (var row in preview.Rows)
            _tableRows.Add(new TableRowItem(row));

        HighlightTableRow = preview.HighlightRow;
        HighlightTableCell = preview.HighlightCell;
        LocatorInfo = locator.ToCanonicalDisplay();

        var truncParts = new List<string>();
        if (preview.TruncatedBefore > 0) truncParts.Add($"上方省略 {preview.TruncatedBefore} 行");
        if (preview.TruncatedAfter > 0) truncParts.Add($"下方省略 {preview.TruncatedAfter} 行");
        TruncationNote = string.Join("，", truncParts);

        PreviewTitle = title;
        IsTextPreview = false;
        IsTablePreview = true;
        IsBinaryPreview = false;
        HasContent = preview.Rows.Count > 0;
    }

    public void LoadBinaryPreview(byte[] data, SourceLocator.BinaryLocator locator, string title)
    {
        ClearCurrentPreview();

        var preview = SafePreviewService.PreviewBinary(data, locator);

        _hexLines.Clear();
        _textLinesOnly.Clear();
        foreach (var hl in preview.HexLines)
            _hexLines.Add(new HexLineItem(hl.Offset, hl.Hex));
        foreach (string tl in preview.TextLines)
            _textLinesOnly.Add(tl);

        LocatorInfo = locator.ToCanonicalDisplay();

        var truncParts = new List<string>();
        if (preview.ByteOffset > 0) truncParts.Add($"前方省略 {preview.ByteOffset} 字节");
        if (preview.TruncatedAfter > 0) truncParts.Add($"后方省略 {preview.TruncatedAfter} 字节");
        TruncationNote = string.Join("，", truncParts);

        PreviewTitle = title;
        IsTextPreview = false;
        IsTablePreview = false;
        IsBinaryPreview = true;
        HasContent = preview.HexLines.Count > 0;
    }

    public void ClearCurrentPreview()
    {
        _textLines.Clear();
        _tableRows.Clear();
        _hexLines.Clear();
        _textLinesOnly.Clear();
        HasContent = false;
        IsTextPreview = false;
        IsTablePreview = false;
        IsBinaryPreview = false;
        PreviewTitle = "";
        LocatorInfo = "";
        TruncationNote = "";
    }
}

// ---------------------------------------------------------------------------
// Display item types
// ---------------------------------------------------------------------------

public sealed record SafePreviewLineItem(int LineNumber, string Text);

public sealed record TableRowItem(IReadOnlyList<string> Cells);

public sealed record HexLineItem(long Offset, string Hex);

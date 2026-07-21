using SecurityReview.Parsers.Structured;

namespace SecurityReview.UnitTests.Parsers;

public sealed class StructuredPathTests
{
    [Fact]
    public void json_path_tracker_empty_returns_empty()
    {
        var tracker = new JsonPathTracker();
        var path = tracker.ToJsonPointer();
        Assert.Equal(string.Empty, path);
    }

    [Fact]
    public void json_path_tracker_nested_object_produces_correct_pointer()
    {
        var tracker = new JsonPathTracker();
        tracker.PushProperty("users");
        tracker.PushIndex(1);
        tracker.PushProperty("token");

        var path = tracker.ToJsonPointer();
        Assert.Equal("/users/1/token", path);
    }

    [Fact]
    public void json_path_tracker_escapes_slash_and_tilde()
    {
        var tracker = new JsonPathTracker();
        tracker.PushProperty("a/b");

        var path = tracker.ToJsonPointer();
        Assert.Equal("/a~1b", path);
    }

    [Fact]
    public void json_path_tracker_escapes_tilde()
    {
        var tracker = new JsonPathTracker();
        tracker.PushProperty("a~b");

        var path = tracker.ToJsonPointer();
        Assert.Equal("/a~0b", path);
    }

    [Fact]
    public void json_path_tracker_escapes_both_chars()
    {
        var tracker = new JsonPathTracker();
        tracker.PushProperty("path/to~file");

        var path = tracker.ToJsonPointer();
        Assert.Equal("/path~1to~0file", path);
    }

    [Fact]
    public void json_path_tracker_pop_removes_segment()
    {
        var tracker = new JsonPathTracker();
        tracker.PushProperty("a");
        tracker.PushProperty("b");
        tracker.Pop();

        var path = tracker.ToJsonPointer();
        Assert.Equal("/a", path);
    }

    [Fact]
    public void json_path_tracker_array_indices_increment()
    {
        var tracker = new JsonPathTracker();
        tracker.PushIndex(0);
        var path0 = tracker.ToJsonPointer();
        Assert.Equal("/0", path0);

        tracker.Pop();
        tracker.PushIndex(5);
        var path5 = tracker.ToJsonPointer();
        Assert.Equal("/5", path5);
    }

    [Fact]
    public void json_path_tracker_depth_tracks_nesting()
    {
        var tracker = new JsonPathTracker();
        Assert.Equal(0, tracker.Depth);

        tracker.PushProperty("a");
        Assert.Equal(1, tracker.Depth);

        tracker.PushIndex(2);
        Assert.Equal(2, tracker.Depth);

        tracker.Pop();
        Assert.Equal(1, tracker.Depth);
    }

    [Fact]
    public void csv_dialect_detector_detects_comma()
    {
        byte[] sample = "a,b,c\n1,2,3\n4,5,6\n7,8,9\n"u8.ToArray();
        var (delim, score, reason) = CsvDialectDetector.Detect(sample);

        Assert.Equal(',', delim);
        Assert.True(score > 0);
        Assert.Null(reason);
    }

    [Fact]
    public void csv_dialect_detector_detects_tab()
    {
        byte[] sample = "a\tb\tc\n1\t2\t3\n4\t5\t6\n"u8.ToArray();
        var (delim, score, reason) = CsvDialectDetector.Detect(sample);

        Assert.Equal('\t', delim);
        Assert.True(score > 0);
        Assert.Null(reason);
    }

    [Fact]
    public void csv_dialect_detector_detects_semicolon()
    {
        byte[] sample = "a;b;c\n1;2;3\n4;5;6\n"u8.ToArray();
        var (delim, score, reason) = CsvDialectDetector.Detect(sample);

        Assert.Equal(';', delim);
        Assert.True(score > 0);
        Assert.Null(reason);
    }

    [Fact]
    public void csv_dialect_detector_detects_pipe()
    {
        byte[] sample = "a|b|c\n1|2|3\n4|5|6\n"u8.ToArray();
        var (delim, score, reason) = CsvDialectDetector.Detect(sample);

        Assert.Equal('|', delim);
        Assert.True(score > 0);
        Assert.Null(reason);
    }

    [Fact]
    public void csv_dialect_detector_ambiguous_returns_fallback()
    {
        byte[] sample = "a,b;c\n1,2,3\n"u8.ToArray();
        var (delim, _, reason) = CsvDialectDetector.Detect(sample);

        // Should detect comma as the dominant delimiter
        Assert.Equal(',', delim);
    }

    [Fact]
    public void csv_dialect_detector_empty_returns_ambiguous()
    {
        var (_, score, reason) = CsvDialectDetector.Detect([]);

        Assert.Equal(0, score);
        Assert.NotNull(reason);
    }

    [Fact]
    public void yaml_event_guard_enforces_event_limit()
    {
        var guard = new YamlEventGuard();
        bool withinLimit = true;
        for (int i = 0; i < YamlEventGuard.MaxEvents + 10; i++)
        {
            if (!guard.RecordEvent())
            {
                withinLimit = false;
                break;
            }
        }

        Assert.False(withinLimit);
        Assert.True(guard.EventCount > YamlEventGuard.MaxEvents);
    }

    [Fact]
    public void yaml_event_guard_enforces_depth_limit()
    {
        var guard = new YamlEventGuard();
        bool withinLimit = true;
        for (int i = 0; i < YamlEventGuard.MaxDepth + 5; i++)
        {
            if (!guard.EnterStructure())
            {
                withinLimit = false;
                break;
            }
        }

        Assert.False(withinLimit);
        Assert.True(guard.Depth > YamlEventGuard.MaxDepth);
    }

    [Fact]
    public void yaml_event_guard_enforces_alias_limit()
    {
        var guard = new YamlEventGuard();
        bool withinLimit = true;
        for (int i = 0; i < YamlEventGuard.MaxAliases + 5; i++)
        {
            if (!guard.RecordAlias($"anchor_{i}"))
            {
                withinLimit = false;
                break;
            }
            guard.CompleteAlias($"anchor_{i}");
        }

        Assert.False(withinLimit);
    }

    [Fact]
    public void yaml_event_guard_detects_alias_cycle()
    {
        var guard = new YamlEventGuard();

        bool first = guard.RecordAlias("cycle");
        bool second = guard.RecordAlias("cycle"); // same anchor — cycle

        Assert.True(first);
        Assert.False(second);
    }

    [Fact]
    public void yaml_event_guard_scalar_limit_check()
    {
        Assert.False(YamlEventGuard.ScalarExceedsLimit(100));
        Assert.True(YamlEventGuard.ScalarExceedsLimit(YamlEventGuard.MaxScalarLength + 1));
    }

    [Fact]
    public void yaml_event_guard_structure_size_limit()
    {
        Assert.False(YamlEventGuard.StructureExceedsLimit(1024));
        Assert.True(YamlEventGuard.StructureExceedsLimit(YamlEventGuard.MaxStructureSize + 1));
    }

    [Fact]
    public void oversize_json_token_skipper_finds_closing_quote()
    {
        byte[] data = "\"hello world\" rest"u8.ToArray();
        long pos = OversizeJsonTokenSkipper.SkipToEnd(data, 1); // start after opening quote

        Assert.Equal(12, pos); // position of closing quote
    }

    [Fact]
    public void oversize_json_token_skipper_handles_escape()
    {
        byte[] data = "\"hello \\\"world\" rest"u8.ToArray();
        long pos = OversizeJsonTokenSkipper.SkipToEnd(data, 1);

        Assert.Equal(14, pos); // closing quote after escaped quote
    }

    [Fact]
    public void oversize_json_token_skipper_returns_neg_when_not_found()
    {
        byte[] data = "\"hello world"u8.ToArray(); // unclosed
        long pos = OversizeJsonTokenSkipper.SkipToEnd(data, 1);

        Assert.Equal(-1, pos);
    }

    [Fact]
    public void oversize_json_token_skipper_extracts_prefix()
    {
        byte[] data = "AAAA..."u8.ToArray();
        string prefix = OversizeJsonTokenSkipper.ExtractPrefix(data);

        Assert.Equal("AAAA...", prefix);
    }
}

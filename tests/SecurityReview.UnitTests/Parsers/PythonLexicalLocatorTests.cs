using SecurityReview.Parsers.Text;

namespace SecurityReview.UnitTests.Parsers;

public sealed class PythonLexicalLocatorTests
{
    [Fact]
    public void empty_input_yields_no_tokens()
    {
        var result = PythonLexicalLocator.Locate(string.Empty);

        Assert.Empty(result.Tokens);
    }

    [Fact]
    public void simple_string_literal_is_recorded_with_location()
    {
        const string source = "x = 'hello'\n";
        var result = PythonLexicalLocator.Locate(source);

        var token = Assert.Single(result.Tokens, t => t.Kind == PythonLexicalKind.StringLiteral && t.Text == "'hello'");
        Assert.Equal(1, token.StartLine);
        Assert.Equal(5, token.StartColumn);
        Assert.Equal(1, token.EndLine);
        Assert.Equal(12, token.EndColumn);
    }

    [Fact]
    public void comment_is_recorded_with_location()
    {
        const string source = "# top comment\nx = 1\n";
        var result = PythonLexicalLocator.Locate(source);

        var comment = Assert.Single(result.Tokens, t => t.Kind == PythonLexicalKind.Comment);
        Assert.Equal("# top comment", comment.Text);
        Assert.Equal(1, comment.StartLine);
        Assert.Equal(1, comment.StartColumn);
        Assert.Equal(1, comment.EndLine);
        Assert.Equal(14, comment.EndColumn);
    }

    [Fact]
    public void double_quoted_string_with_escape_is_recorded()
    {
        const string source = "msg = \"a\\nb\"\n";
        var result = PythonLexicalLocator.Locate(source);

        var token = Assert.Single(result.Tokens, t => t.Kind == PythonLexicalKind.StringLiteral && t.Text == "\"a\\nb\"");
        Assert.Equal(1, token.StartLine);
        Assert.Equal(7, token.StartColumn);
    }

    [Fact]
    public void raw_string_is_classified_as_raw()
    {
        const string source = "p = r'C:\\Users\\guest'\n";
        var result = PythonLexicalLocator.Locate(source);

        var token = Assert.Single(result.Tokens, t => t.Kind == PythonLexicalKind.RawString);
        Assert.Equal("r'C:\\Users\\guest'", token.Text);
    }

    [Fact]
    public void bytes_literal_is_classified_as_bytes()
    {
        const string source = "data = b'\\x00\\x01'\n";
        var result = PythonLexicalLocator.Locate(source);

        var token = Assert.Single(result.Tokens, t => t.Kind == PythonLexicalKind.Bytes);
        Assert.Equal("b'\\x00\\x01'", token.Text);
    }

    [Fact]
    public void fstring_is_classified_as_fstring()
    {
        const string source = "name = f'hello {user}'\n";
        var result = PythonLexicalLocator.Locate(source);

        var token = Assert.Single(result.Tokens, t => t.Kind == PythonLexicalKind.FString);
        Assert.Equal("f'hello {user}'", token.Text);
    }

    [Fact]
    public void triple_quoted_string_is_classified_as_triple()
    {
        const string source = "doc = \"\"\"\nhello\nworld\n\"\"\"\n";
        var result = PythonLexicalLocator.Locate(source);

        var token = Assert.Single(result.Tokens, t => t.Kind == PythonLexicalKind.TripleString);
        Assert.Contains("hello", token.Text);
        Assert.Equal(1, token.StartLine);
        Assert.Equal(7, token.StartColumn);
    }

    [Fact]
    public void escaped_newline_in_string_continues_on_next_line()
    {
        const string source = "msg = 'a \\\n b'\n";
        var result = PythonLexicalLocator.Locate(source);

        var token = Assert.Single(result.Tokens, t => t.Kind == PythonLexicalKind.StringLiteral);
        Assert.Equal(1, token.StartLine);
        Assert.Equal(7, token.StartColumn);
        Assert.Equal(2, token.EndLine);
    }

    [Fact]
    public void non_ascii_identifier_after_string_is_unaffected()
    {
        const string source = "名前 = 1\nx = 'literal'\n";
        var result = PythonLexicalLocator.Locate(source);

        var token = Assert.Single(result.Tokens, t => t.Kind == PythonLexicalKind.StringLiteral);
        Assert.Equal("'literal'", token.Text);
        Assert.Equal(2, token.StartLine);
        Assert.Equal(5, token.StartColumn);
    }

    [Fact]
    public void unmatched_quote_records_truncated_token_and_tail_gap()
    {
        const string source = "x = 'oops\n";
        var result = PythonLexicalLocator.Locate(source);

        var token = Assert.Single(result.Tokens, t => t.Kind == PythonLexicalKind.StringLiteral);
        Assert.Equal("'oops", token.Text);
        Assert.True(result.HasInvalidTail);
    }

    [Fact]
    public void hash_inside_string_is_not_a_comment()
    {
        const string source = "x = 'a # not a comment'\n";
        var result = PythonLexicalLocator.Locate(source);

        Assert.DoesNotContain(result.Tokens, t => t.Kind == PythonLexicalKind.Comment);
        Assert.Contains(result.Tokens, t => t.Kind == PythonLexicalKind.StringLiteral);
    }

    [Fact]
    public void trailing_comment_after_code_is_recorded()
    {
        const string source = "x = 1   # trailing\n";
        var result = PythonLexicalLocator.Locate(source);

        var comment = Assert.Single(result.Tokens, t => t.Kind == PythonLexicalKind.Comment);
        Assert.Equal("# trailing", comment.Text);
        Assert.Equal(1, comment.StartLine);
        Assert.Equal(9, comment.StartColumn);
    }

    [Fact]
    public void triple_quoted_with_embedded_double_quotes()
    {
        const string source = "doc = \"\"\"contains \"quote\" inside\"\"\"\n";
        var result = PythonLexicalLocator.Locate(source);

        var token = Assert.Single(result.Tokens, t => t.Kind == PythonLexicalKind.TripleString);
        Assert.Equal("\"\"\"contains \"quote\" inside\"\"\"", token.Text);
    }

    [Fact]
    public void invalid_tail_does_not_throw()
    {
        const string source = "x = '\x01broken\n";
        var result = PythonLexicalLocator.Locate(source);

        Assert.True(result.HasInvalidTail);
    }

    [Fact]
    public void raw_triple_quoted_keeps_backslashes_literal()
    {
        const string source = "p = r'''a\\nb'''\n";
        var result = PythonLexicalLocator.Locate(source);

        var token = Assert.Single(result.Tokens, t => t.Kind == PythonLexicalKind.RawTripleString);
        Assert.Equal("r'''a\\nb'''", token.Text);
    }
}

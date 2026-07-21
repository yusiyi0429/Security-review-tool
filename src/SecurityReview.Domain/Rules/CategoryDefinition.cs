using System.Text.Json.Serialization;
using SecurityReview.Domain.Assets;

namespace SecurityReview.Domain.Rules;

public sealed record CategoryDefinition
{
    [JsonConverter(typeof(CategoryIdJsonConverter))]
    public CategoryId CategoryId { get; init; }
    public string Name { get; init; } = "";
    public string Description { get; init; } = "";
    public bool Enabled { get; init; } = true;

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(Name))
        {
            errors.Add("CategoryDefinition Name must not be empty.");
        }

        return errors;
    }
}

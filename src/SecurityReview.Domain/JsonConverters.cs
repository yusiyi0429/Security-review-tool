using System.Text.Json;
using System.Text.Json.Serialization;
using SecurityReview.Domain.Assets;

namespace SecurityReview.Domain;

public sealed class AssetTypeIdJsonConverter : JsonConverter<AssetTypeId>
{
    public override AssetTypeId Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value is not null ? AssetTypeId.Parse(value) : default;
    }

    public override void Write(Utf8JsonWriter writer, AssetTypeId value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.Value);
    }

    public override AssetTypeId ReadAsPropertyName(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => AssetTypeId.Parse(reader.GetString()!);

    public override void WriteAsPropertyName(Utf8JsonWriter writer, AssetTypeId value, JsonSerializerOptions options)
    {
        writer.WritePropertyName(value.Value);
    }
}

public sealed class CategoryIdJsonConverter : JsonConverter<CategoryId>
{
    public override CategoryId Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value is not null ? CategoryId.Parse(value) : default;
    }

    public override void Write(Utf8JsonWriter writer, CategoryId value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.Value);
    }

    public override CategoryId ReadAsPropertyName(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => CategoryId.Parse(reader.GetString()!);

    public override void WriteAsPropertyName(Utf8JsonWriter writer, CategoryId value, JsonSerializerOptions options)
    {
        writer.WritePropertyName(value.Value);
    }
}

public sealed class RuleIdJsonConverter : JsonConverter<RuleId>
{
    public override RuleId Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        return new RuleId(reader.GetString() ?? "");
    }

    public override void Write(Utf8JsonWriter writer, RuleId value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.Value);
    }
}

public sealed class DetectorIdJsonConverter : JsonConverter<DetectorId>
{
    public override DetectorId Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        return new DetectorId(reader.GetString() ?? "");
    }

    public override void Write(Utf8JsonWriter writer, DetectorId value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.Value);
    }
}

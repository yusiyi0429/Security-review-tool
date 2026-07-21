namespace SecurityReview.Application.Abstractions;

/// <summary>
/// Protects named secrets using per-credential DPAPI encryption with
/// name-derived optional entropy. Filenames are SHA-256 of the logical
/// name, not the credential text.
/// </summary>
public interface ISecretStore
{
    void Save(string name, string value);
    string Load(string name);
    void Delete(string name);
}

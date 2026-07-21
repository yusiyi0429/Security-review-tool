namespace SecurityReview.Parsers.Models;

/// <summary>
/// Kind of model format detected by the parser.
/// </summary>
public enum ModelKind
{
    Unknown,
    SafeTensors,
    Gguf,
    Onnx,
    Pickle,
    PyTorchArchive,
}

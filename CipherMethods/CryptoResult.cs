using System.Text.Json.Nodes;

namespace PasswordManager.CipherMethods;

public class CryptoResult
{
    public readonly byte[] Data;
    public readonly JsonObject Metadata;

    public CryptoResult(byte[] data, JsonObject metadata)
    {
        this.Data = data;
        this.Metadata = metadata;
    }
}
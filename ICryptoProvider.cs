using System.Text.Json.Nodes;

namespace PasswordManager.workspace;


public interface IEncryptionProvider : IDisposable
{
    public bool CanUse { get; } 
    CryptoResult Encrypt(byte[] plainText);
}

public interface IDecryptionProvider : IDisposable
{
    public bool CanUse { get; }
    
    byte[] Decrypt(byte[] cipherText, out bool passphraseCorrect);
}


public interface ICryptoProvider : IEncryptionProvider, IDecryptionProvider
{

}


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
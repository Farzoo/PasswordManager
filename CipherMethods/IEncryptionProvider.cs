namespace PasswordManager.CipherMethods;

public interface IEncryptionProvider : IDisposable
{
    public bool CanUse { get; }
    public string Identifier { get; }
    CryptoResult Encrypt(byte[] plainText);
}
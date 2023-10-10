namespace PasswordManager.CipherMethods;

public interface IDecryptionProvider : IDisposable
{
    public bool CanUse { get; }
    public string Identifier { get; }
    byte[] Decrypt(byte[] cipherText, out bool passphraseCorrect);
}
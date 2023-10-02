using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace PasswordManager;

public class AesCryptoProvider : ICryptoProvider
{
    private readonly IKdfProvider _kdfProvider;

    private readonly byte[] _nonce;
    private readonly byte[] _tag;
    private readonly byte[]? _additionalData;
    
    private readonly int _keySize;
    
    private readonly int _nonceSize;
    private readonly int _saltSize;
    public bool CanUse { get; private set; } = true;
    
    public string Identifier => IDENTIFIER;

    public const string IDENTIFIER = "AES_GCM";

    private AesCryptoProvider(IKdfProvider kdfProvider, int keySize, int tagSize, int nonceSize)
    {
        this._kdfProvider = kdfProvider;
        
        this._keySize = keySize;
        this._nonceSize = nonceSize;

        this._tag = new byte[tagSize / 8];
    }

    private AesCryptoProvider(IKdfProvider kdfProvider, byte[] nonce, byte[] tag, byte[]? additionalData, int keySize)
        : this(kdfProvider, keySize,  tag.Length, nonce.Length)
    {
        this._nonce = nonce;
        this._tag = tag;
        this._additionalData = additionalData;
    }

    public static AesCryptoProvider CreateEncryptor(IKdfProvider kdfProvider, int keySize, int tagSize, int nonceSize)
    {
        return new AesCryptoProvider(kdfProvider, keySize,  tagSize, nonceSize);
    }

    public static AesCryptoProvider CreateDecryptor(IKdfProvider kdfProvider, byte[] nonce, byte[] tag, byte[]? additionalData, int keySize)
    {
        return new AesCryptoProvider(kdfProvider, nonce, tag, additionalData, keySize);
    }

    public CryptoResult Encrypt(byte[] plainText)
    {
        if (!this.CanUse) throw new InvalidOperationException("This instance of AesCryptoProvider is not usable anymore.");

        this.CanUse = false;
        
        this._kdfProvider.Reset();

        var key = this._kdfProvider.GetBytes(this._keySize / 8);
        
        using var aes = new AesGcm(key);

        var nonce = RandomNumberGenerator.GetBytes(this._nonceSize / 8);

        var cipherText = new byte[plainText.Length];
        
        aes.Encrypt(nonce, plainText, cipherText, this._tag, this._additionalData);

        JsonObject metadata = new()
        {
            {"nonce", Convert.ToBase64String(nonce)},
            {"tag", Convert.ToBase64String(this._tag)},
            {"keySize", this._keySize}
        };
        
        if(this._additionalData != null)
            metadata.Add("additionalData", Convert.ToBase64String(this._additionalData));
        
        return new CryptoResult(cipherText, metadata);
    }

    public byte[] Decrypt(byte[] cipherText, out bool passphraseCorrect)
    {
        if (!this.CanUse) throw new InvalidOperationException("This instance of AesCryptoProvider is not usable anymore.");

        this.CanUse = false;
        
        this._kdfProvider.Reset();

        var key = this._kdfProvider.GetBytes(this._keySize / 8);
        
        using var aes = new AesGcm(key);
        
        var plainText = new byte[cipherText.Length];
        
        aes.Decrypt(this._nonce, cipherText, this._tag, plainText, this._additionalData);

        passphraseCorrect = true;

        return plainText;
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);
    }
}

using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using PasswordManager.CipherMethods;
using PasswordManager.KdfMethods;
using PasswordManager.Misc;
using PasswordManager.Repositories;

namespace PasswordManager.PasswordManagers;



public class PasswordManager: IPasswordManager<PasswordManager.PasswordData>
{
    private readonly IPasswordRepository<string, PasswordData> _passwordRepository;


    private readonly Func<byte[], string, JsonObject, IKdfProvider?> _kdfFactory;
    private readonly Func<byte[], IKdfProvider> _defaultKdfFactory;
    
    private readonly Func<string, IKdfProvider, JsonObject, IEncryptionProvider?> _encryptionProviderFactory;
    private readonly Func<IKdfProvider, IEncryptionProvider> _defaultEncryptionProviderFactory;
    
    private readonly Func<string, IKdfProvider, JsonObject, IDecryptionProvider?> _decryptionProviderFactory;

    public PasswordManager(
        IPasswordRepository<string, PasswordData> passwordRepository,
        Func<byte[], string, JsonObject, IKdfProvider?> kdfFactory, 
        Func<byte[], IKdfProvider> defaultKdfFactory, 
        Func<string, IKdfProvider, JsonObject, IEncryptionProvider?> encryptionProviderFactory,
        Func<IKdfProvider, IEncryptionProvider> defaultEncryptionProviderFactory,
        Func<string, IKdfProvider, JsonObject, IDecryptionProvider?> decryptionProviderFactory
    )
    {
        this._passwordRepository = passwordRepository;
        this._encryptionProviderFactory = encryptionProviderFactory;
        this._defaultEncryptionProviderFactory = defaultEncryptionProviderFactory;
        this._kdfFactory = kdfFactory;
        this._defaultKdfFactory = defaultKdfFactory;
        this._decryptionProviderFactory = decryptionProviderFactory;
    }

    private const int SaltSize = 16;

    public async Task StoreAsync(string key, byte[] password, byte[] passphrase)
    {
        if(password is null || password.Length == 0)
        {
            throw new ArgumentException("Password cannot be null or empty");
        }
        
        if(await this._passwordRepository.ContainsAsync(key))
        {
            throw new ArgumentException($"Key {key} already exists");
        }

        var salt = new byte[SaltSize];
        Utils.GenerateSalt(salt);

        var kdfProvider = this._defaultKdfFactory(passphrase);
        
        var encryptionProvider = this._defaultEncryptionProviderFactory(kdfProvider);

        var result = encryptionProvider.Encrypt(password);

        await this._passwordRepository.StoreAsync(key, 
            new PasswordData(
                result.Data,
                encryptionProvider.Identifier,
                result.Metadata,
                kdfProvider.Identifier,
                kdfProvider.Metadata
            )
        );
    }

    public async Task<byte[]> RetrieveAsync(string key, byte[] passphrase)
    {
        var data = await this._passwordRepository.RetrieveAsync(key);

        string encryptionMethod = data.CipherMethod;
        string kdfMethod = data.KdfMethod;

        var kdfProvider = this._kdfFactory(
            passphrase,
            kdfMethod,
            data.KdfMetadata
        );
        
        if (kdfProvider is null) throw new ArgumentOutOfRangeException($"KDF provider {data.KdfMetadata.ToJsonString(new JsonSerializerOptions(){WriteIndented = true})} is not supported");

        var encryptionProvider = this._decryptionProviderFactory(
            data.CipherMethod,
            kdfProvider,
            data.CipherMetadata
        );

        if (encryptionProvider is null) throw new ArgumentOutOfRangeException($"Encryption provider {encryptionMethod} is not supported");
       
        try
        {
            var plainText = encryptionProvider.Decrypt(data.EncryptedPassword, out var _);
            return await Task.FromResult(plainText);
        } catch (CryptographicException ex) {
            throw new ArgumentException("Passphrase is incorrect", nameof(passphrase), ex);
        }
    }

    public async Task UpdateAsync(string key, byte[] newPassword, byte[] passphrase)
    {
        var success = await this.InternalDeleteAsync(key, passphrase);
        if (success) await this.StoreAsync(key, newPassword, passphrase);
    }

    public async Task DeleteAsync(string key, byte[] passphrase)
    {
        await this.InternalDeleteAsync(key, passphrase);
    }

    public async Task<IEnumerable<KeyValuePair<string, PasswordData>>> RetrieveAllAsync()
    {
        return await this._passwordRepository.RetrieveAllAsync();
    }

    private async Task<bool> InternalDeleteAsync(string key, byte[] passphrase)
    {
        var data = await this._passwordRepository.RetrieveAsync(key);
        var kdfProvider = this._kdfFactory(passphrase, data.KdfMethod, data.KdfMetadata);
        if (kdfProvider is null) throw new ArgumentOutOfRangeException($"KDF provider {data.KdfMetadata.ToJsonString(new JsonSerializerOptions(){WriteIndented = true})} is not supported");
        var encryptionProvider = this._decryptionProviderFactory(data.CipherMethod, kdfProvider, data.CipherMetadata);
        if (encryptionProvider is null) throw new ArgumentOutOfRangeException($"Encryption provider {data.CipherMetadata.ToJsonString(new JsonSerializerOptions(){WriteIndented = true})} is not supported");

        try {
            var decryptedPassword = encryptionProvider.Decrypt(data.EncryptedPassword, out var passphraseCorrect);
            if (!passphraseCorrect) throw new CryptographicException("Passphrase is incorrect");
            await this._passwordRepository.DeleteAsync(key);
            return true;
        } catch (CryptographicException ex) {
            throw new ArgumentException("Passphrase is incorrect", nameof(passphrase), ex);
        }
    }

    public class PasswordData
    {
        public readonly byte[] EncryptedPassword;
        
        public readonly string CipherMethod;
        public readonly JsonObject CipherMetadata;
        
        public readonly string KdfMethod;
        public readonly JsonObject KdfMetadata;

        public PasswordData(
            byte[] encryptedPassword, string cipherMethod, JsonObject cipherMetadata, string kdfMethod, JsonObject kdfMetadata
        )
        {
            this.EncryptedPassword = encryptedPassword;
            this.CipherMethod = cipherMethod;
            this.CipherMetadata = cipherMetadata;
            this.KdfMethod = kdfMethod;
            this.KdfMetadata = kdfMetadata;
        }
    }
}

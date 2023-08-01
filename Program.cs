using System.Buffers;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace PasswordManager.workspace;

class Program
{
    private enum State
    {
        MainMenu,
        Store,
        Retrieve,
        Update,
        Delete,
        Save,
        Quit
    }
    
    static void Main(string[] args)
    {
        var passwordManager = new PasswordManager(
            new InMemoryPasswordRepository<string, PasswordManager.PasswordData>(),
            KdfProviderFactory,
            DefaultKdfProviderFactory,
            EncryptionProviderFactory,
            DefaultEncryptionProviderFactory,
            DecryptionProviderFactory
        );
        
        State state = State.MainMenu;

        string key = null;
        byte[] passphrase = null;
        byte[] password = null;

        while (true)
        {
            switch (state)
            {
                case State.MainMenu:
                    Console.Clear();
                    Console.WriteLine($"Available memory: {GC.GetGCMemoryInfo().TotalAvailableMemoryBytes / 1024 / 1024} MB");
                    Console.WriteLine("Choose an option:");
                    Console.WriteLine("1. Store a password");
                    Console.WriteLine("2. Retrieve a password");
                    Console.WriteLine("3. Update a password");
                    Console.WriteLine("4. Delete a password");
                    Console.WriteLine("5. Save");
                    Console.WriteLine("6. Quit");

                    string option = Console.ReadLine();

                    switch (option)
                    {
                        case "1":
                            state = State.Store;
                            break;
                        case "2":
                            state = State.Retrieve;
                            break;
                        case "3":
                            state = State.Update;
                            break;
                        case "4":
                            state = State.Delete;
                            break;
                        case "5":
                            state = State.Save;
                            break;
                        case "6":
                            state = State.Quit;
                            break;
                        default:
                            Console.WriteLine("Invalid option. Please try again.");
                            break;
                    }

                    if (state != State.MainMenu) Console.Clear();
                    break;

                case State.Store:
                    Console.WriteLine("Enter a key:");
                    key = Console.ReadLine();

                    Console.WriteLine("Enter a passphrase:");
                    passphrase = Encoding.UTF8.GetBytes(Console.ReadLine());

                    Console.WriteLine("Enter a password to store:");
                    password = Encoding.UTF8.GetBytes(Console.ReadLine());

                    passwordManager.StoreAsync(key, password, passphrase).Wait();
                    Console.WriteLine("Password stored successfully.");

                    state = State.MainMenu;
                    break;

                case State.Retrieve:
                    Console.WriteLine("Enter a key:");
                    key = Console.ReadLine();

                    Console.WriteLine("Enter a passphrase:");
                    passphrase = Encoding.UTF8.GetBytes(Console.ReadLine());

                    byte[] retrievedPassword = passwordManager.RetrieveAsync(key, passphrase).Result;
                    
                    Console.WriteLine($"Retrieved password: {Encoding.UTF8.GetString(retrievedPassword)}");
                    Console.WriteLine("Press any key to continue.");
                    
                    Console.ReadKey();
                    
                    state = State.MainMenu;
                    break;

                case State.Update:
                    Console.WriteLine("Enter a key:");
                    key = Console.ReadLine();

                    Console.WriteLine("Enter a passphrase:");
                    passphrase = Encoding.UTF8.GetBytes(Console.ReadLine());

                    Console.WriteLine("Enter a new password:");
                    byte[] newPassword = Encoding.UTF8.GetBytes(Console.ReadLine());
                    passwordManager.UpdateAsync(key, newPassword, passphrase).Wait();
                    Console.WriteLine("Password updated successfully.");
                    
                    state = State.MainMenu;
                    break;
                
                case State.Save:
                    
                    JsonObject json = new();
                    foreach (var row in passwordManager.RetrieveAllAsync().Result)
                    {
                        var obj = new JsonObject()
                        {
                            {"cipherText", Convert.ToBase64String(row.Value.EncryptedPassword)},
                            {"kdfParams", JsonSerializer.SerializeToNode(row.Value.KdfMetadata)},
                            {"cipherParams", JsonSerializer.SerializeToNode(row.Value.CipherMetadata)}
                        };
                        
                        json.Add(row.Key, obj);
                    }
                    var jsonSerializerOptions = new JsonSerializerOptions();
                    jsonSerializerOptions.WriteIndented = true;

                    File.WriteAllTextAsync("passwords.json", json.ToJsonString(jsonSerializerOptions)).Wait();
                    Console.WriteLine("Repository saved to passwords.json.");

                    state = State.MainMenu;
                    break;

                case State.Delete:
                    Console.WriteLine("Enter a key:");
                    key = Console.ReadLine();

                    Console.WriteLine("Enter a passphrase:");
                    passphrase = Encoding.UTF8.GetBytes(Console.ReadLine());

                    passwordManager.DeleteAsync(key, passphrase).Wait();
                    Console.WriteLine("Password deleted successfully.");

                    state = State.MainMenu;
                    break;

                case State.Quit:
                    return;
            }
        }
    }

    private static IKdfProvider DefaultKdfProviderFactory(byte[] passphrase)
    {
        Console.WriteLine($"Available memory: {GC.GetGCMemoryInfo().TotalAvailableMemoryBytes}");
        var memory = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes / 1024 / 4;
        // floor to nearest power of 2
        memory = (int)Math.Pow(2, Math.Floor(Math.Log(memory, 2)));
        Console.WriteLine($"Using {memory} MB of memory for KDF.");
        return new Argon2idProvider(
            passphrase, 
            RandomNumberGenerator.GetBytes(96 / 8),
            10,
            (int) memory,
            Environment.ProcessorCount > 8 ? 8 : Environment.ProcessorCount
        );
    }

    private static IEncryptionProvider DefaultEncryptionProviderFactory(IKdfProvider kdfProvider)
    {
        return AesCryptoProvider.CreateEncryptor(
            kdfProvider, 
            256, 
            AesGcm.TagByteSizes.MaxSize * 8, 
            AesGcm.NonceByteSizes.MaxSize * 8
        );
    }

    private static IKdfProvider KdfProviderFactory(byte[] passphrase, JsonObject param)
    {
        var method = param.GetValueOrThrow<string>("method");

        return method switch
        {
            "Argon2id" => new Argon2idProvider(
                passphrase, 
                Convert.FromBase64String(param.GetValueOrThrow<string>("salt")),
                param.GetValueOrThrow<int>("iterations"),
                param.GetValueOrThrow<int>("memorySize"),
                param.GetValueOrThrow<int>("degreeOfParallelism")
            ),
            _ => throw new ArgumentOutOfRangeException(nameof(method), $"Unknown KDF method {method}")
        };
    }

    private static ICryptoProvider EncryptionProviderFactory(JsonObject param, IKdfProvider kdfProvider)
    {
        var method = param.GetValueOrThrow<string>("method");

        return method switch
        {
            AesCryptoProvider.Identifier => AesCryptoProvider.CreateEncryptor(
                kdfProvider, 
                param.GetValueOrThrow<int>("keySize"), 
                param.GetValueOrThrow<int>("tagSize"), 
                param.GetValueOrThrow<int>("nonceSize")
            ),
            _ => throw new ArgumentOutOfRangeException(nameof(method), $"Unknown encryption method {method}")
        };
    }

    private static IDecryptionProvider DecryptionProviderFactory(JsonObject param, IKdfProvider kdfProvider)
    {
        var method = param.GetValueOrThrow<string>("method");

        return method switch
        {
            AesCryptoProvider.Identifier => AesCryptoProvider.CreateDecryptor(
                kdfProvider,
                Convert.FromBase64String(param.GetValueOrThrow<string>("nonce")),
                Convert.FromBase64String(param.GetValueOrThrow<string>("tag")),
                param.TryGetValue<string>("additionalData", out var additionalData) ? Convert.FromBase64String(additionalData!) : null,
                param.GetValueOrThrow<int>("keySize")
            ),
            _ => throw new ArgumentOutOfRangeException(nameof(method), $"Unknown encryption method {method}")
        };
    }
}

using System.Text.Json.Nodes;
using Konscious.Security.Cryptography;

namespace PasswordManager.workspace;

public class Argon2idProvider : IKdfProvider
{
    private readonly Argon2id _argon2id;
    private readonly JsonObject _parameters;
    
    private const string Identifier = "Argon2id";

    public Argon2idProvider(byte[] passphrase, byte[] salt, int iterations, int memorySize, int degreeOfParallelism)
    {

        this._argon2id = new Argon2id(passphrase)
        {
            Salt = salt,
            Iterations = iterations,
            MemorySize = memorySize,
            DegreeOfParallelism = degreeOfParallelism
        };
        
        this._parameters = new JsonObject() 
        {
            {"method", Identifier},
            {"salt", Convert.ToBase64String(salt)},
            {"iterations", iterations},
            {"memorySize", memorySize},
            {"degreeOfParallelism", degreeOfParallelism}
        };
    }

    public void Dispose()
    {
        this._argon2id.Dispose();
        GC.SuppressFinalize(this);
    }

    public byte[] GetBytes(int cb)
    {
        return this._argon2id.GetBytes(cb);
    }

    public void Reset()
    {
        this._argon2id.Reset();
    }

    public JsonObject Metadata => this._parameters;
}
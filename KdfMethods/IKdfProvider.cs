using System.Text.Json.Nodes;

namespace PasswordManager.KdfMethods;

public interface IKdfProvider : IDisposable
{
    public byte[] GetBytes(int cb);
    public void Reset();
    
    public JsonObject Metadata { get; }
    public string Identifier { get; }
}
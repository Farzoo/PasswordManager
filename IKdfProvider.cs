using System.Text.Json.Nodes;

namespace PasswordManager.workspace;

public interface IKdfProvider : IDisposable
{
    public byte[] GetBytes(int cb);
    public void Reset();
    
    public JsonObject Metadata { get; }
}
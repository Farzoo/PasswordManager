namespace PasswordManager.workspace;

public interface IPasswordManager<TEntity> where TEntity : notnull
{
    public Task StoreAsync(string key, byte[] data, byte[] passphrase);
    public Task<byte[]> RetrieveAsync(string key, byte[] passphrase);
    public Task UpdateAsync(string key, byte[] data, byte[] passphrase);
    public Task DeleteAsync(string key, byte[] passphrase);
    
    public Task<IEnumerable<KeyValuePair<string, TEntity>>> RetrieveAllAsync();
}

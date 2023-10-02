namespace PasswordManager;

public class InMemoryPasswordRepository<TKey, TEntity>  : IPasswordRepository<TKey, TEntity> where TKey : notnull
{
    private readonly Dictionary<TKey, TEntity> _passwords = new Dictionary<TKey, TEntity>();
    public Task StoreAsync(TKey key, TEntity data)
    {
        if (!this._passwords.ContainsKey(key))
        {
            this._passwords.Add(key, data);
        }
        else
        {
            throw new ArgumentException("Key already exists.");
        }
        return Task.CompletedTask;
    }

    public Task<TEntity> RetrieveAsync(TKey key)
    {
        try
        {
            return Task.FromResult(this._passwords[key]);
        } catch (KeyNotFoundException e)
        {
            return Task.FromException<TEntity>(e);
        }
    }

    public Task UpdateAsync(TKey key, TEntity data)
    {
        if (this._passwords.TryGetValue(key, out var _))
        {
            this._passwords[key] = data;
        }
        else
        {
            this._passwords.Add(key, data);
        }
        
        return Task.CompletedTask;
    }

    public Task DeleteAsync(TKey key)
    {
        this._passwords.Remove(key);
        return Task.CompletedTask;
    }

    public async Task<bool> ContainsAsync(TKey key)
    {
        return await Task.FromResult(this._passwords.ContainsKey(key));
    }

    public async Task<IEnumerable<KeyValuePair<TKey, TEntity>>> RetrieveAllAsync()
    {
        return await Task.FromResult(this._passwords.AsEnumerable());
    }
}
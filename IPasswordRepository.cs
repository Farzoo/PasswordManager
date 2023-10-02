namespace PasswordManager;

public interface IPasswordRepository<TKey, TEntity>
{
    Task StoreAsync(TKey key, TEntity data);
    Task<TEntity> RetrieveAsync(TKey key);
    Task UpdateAsync(TKey key, TEntity data);
    Task DeleteAsync(TKey key);
    
    Task<bool> ContainsAsync(TKey key);
    
    Task<IEnumerable<KeyValuePair<TKey, TEntity>>> RetrieveAllAsync();
}
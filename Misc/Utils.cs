using System.Security.Cryptography;

namespace PasswordManager.Misc;

public static class Utils
{
    public static void GenerateSalt(Span<byte> buffer)
    {
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(buffer);
    }
}
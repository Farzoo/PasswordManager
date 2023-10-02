using System.Text.Json;
using System.Text.Json.Nodes;

namespace PasswordManager;

internal static class JsonExtensions
{
    internal static T GetValueOrThrow<T>(this JsonObject parameters, string key)
    {
        if (!parameters.TryGetPropertyValue(key, out var node))
        {
            throw new JsonException($"node {key} is missing");
        }

        var nodeValue = node as JsonValue ?? throw new JsonException($"Parameter {key} is not a primitive value");
        
        if (!nodeValue!.TryGetValue(out T? value))
        {
            throw new JsonException($"Value of parameter {key} is not of type {typeof(T)}");
        }
        
        return value;
    }

    internal static bool TryGetValue<T>(this JsonObject parameters, string key, out T? value)
    {
        value = default;
        if (!parameters.TryGetPropertyValue(key, out var node)) return false;
        return node is JsonValue nodeValue && nodeValue.TryGetValue(out value);
    }
}
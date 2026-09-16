using StackExchange.Redis;
using UserService.Models;
using System.Security.Cryptography;

namespace UserService.Services;

public sealed class UserDirectoryService : IUserDirectoryService
{
    private readonly ISupabaseAuthClient _supabase;
    private readonly IDatabase _redis;

    private const string P256Oid =
    "1.2.840.10045.3.1.7";

    public UserDirectoryService(
        ISupabaseAuthClient supabase,
        IConnectionMultiplexer redis
    )
    {
        _supabase = supabase;
        _redis = redis.GetDatabase();
    }

    public async Task<IReadOnlyList<UserDirectoryEntryResponse>>
        GetUsersAsync(
            string currentUserId,
            CancellationToken cancellationToken
        )
    {
        var users = await _supabase.GetConfirmedUsersAsync(
            cancellationToken
        );

        var otherUsers = users
            .Where(user => user.UserId != currentUserId)
            .ToArray();

        var entries = await Task.WhenAll(
            otherUsers.Select(async user =>
            {
                cancellationToken.ThrowIfCancellationRequested();

                var isOnline = await _redis.KeyExistsAsync(
                    GetOnlineKey(user.UserId)
                );

                return new UserDirectoryEntryResponse(
                    user.UserId,
                    user.Email,
                    isOnline
                );
            })
        );

        return entries
            .OrderBy(
                entry => entry.DisplayName,
                StringComparer.OrdinalIgnoreCase
            )
            .ToArray();
    }

    public async Task<PublicKeyResponse>
    PublishPublicKeyAsync(
        string currentUserId,
        PublishPublicKeyRequest request,
        CancellationToken cancellationToken
    )
{
    var validated =
        ValidatePublicKey(
            request.PublicKey
        );

    var stored =
        new SupabaseStoredPublicKey(
            validated.KeyId,
            validated.PublicKey,
            DateTimeOffset.UtcNow
        );

    await _supabase.StorePublicKeyAsync(
        currentUserId,
        stored,
        cancellationToken
    );

    return new PublicKeyResponse(
        currentUserId,
        stored.KeyId,
        stored.PublicKey,
        stored.UpdatedAt
    );
}

public async Task<PublicKeyResponse?>
    GetPublicKeyAsync(
        string userId,
        CancellationToken cancellationToken
    )
{
    var stored =
        await _supabase.GetPublicKeyAsync(
            userId,
            cancellationToken
        );

    if (stored is null)
    {
        return null;
    }

    var validated =
        ValidatePublicKey(
            stored.PublicKey
        );

    if (
        validated.KeyId != stored.KeyId ||
        stored.UpdatedAt ==
            DateTimeOffset.MinValue
    )
    {
        throw new InvalidOperationException(
            "Der gespeicherte Public Key ist ungültig."
        );
    }

    return new PublicKeyResponse(
        userId,
        stored.KeyId,
        validated.PublicKey,
        stored.UpdatedAt
    );
}

private static ValidatedPublicKey
    ValidatePublicKey(
        string encodedPublicKey
    )
{
    if (
        string.IsNullOrWhiteSpace(
            encodedPublicKey
        ) ||
        encodedPublicKey.Length > 512 ||
        encodedPublicKey.Length % 4 == 1 ||
        !encodedPublicKey.All(
            character =>
                char.IsAsciiLetterOrDigit(
                    character
                ) ||
                character is '-' or '_'
        )
    )
    {
        throw new ArgumentException(
            "Der Public Key ist kein gültiger Base64url-Wert."
        );
    }

    byte[] spki;

    try
    {
        var base64 =
            encodedPublicKey
                .Replace('-', '+')
                .Replace('_', '/');

        base64 += new string(
            '=',
            (4 - base64.Length % 4) % 4
        );

        spki =
            Convert.FromBase64String(
                base64
            );
    }
    catch (FormatException)
    {
        throw new ArgumentException(
            "Der Public Key ist kein gültiger Base64url-Wert."
        );
    }

    try
    {
        using var key =
            ECDiffieHellman.Create();

        key.ImportSubjectPublicKeyInfo(
            spki,
            out var bytesRead
        );

        var curve =
            key.ExportParameters(false)
                .Curve;

        if (
            bytesRead != spki.Length ||
            !curve.IsNamed ||
            curve.Oid.Value != P256Oid
        )
        {
            throw new ArgumentException(
                "Der Public Key muss ein P-256-SPKI-Schlüssel sein."
            );
        }
    }
    catch (CryptographicException)
    {
        throw new ArgumentException(
            "Der Public Key muss ein P-256-SPKI-Schlüssel sein."
        );
    }

    var canonicalPublicKey =
        Convert
            .ToBase64String(spki)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    var keyId =
        "sha256:" +
        Convert
            .ToBase64String(
                SHA256.HashData(spki)
            )
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    return new ValidatedPublicKey(
        keyId,
        canonicalPublicKey
    );
}

private sealed record
    ValidatedPublicKey(
        string KeyId,
        string PublicKey
    );

private static string GetOnlineKey(string userId)
    {
        return $"eva-chat:online:{userId}";
    }
}
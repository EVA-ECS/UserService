using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using UserService.Configuration;
using UserService.Models;

namespace UserService.Services;

public sealed class SupabaseAuthClient : ISupabaseAuthClient
{
    private const int UserPageSize = 1000;

    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web);

    private readonly HttpClient _httpClient;
    private readonly ILogger<SupabaseAuthClient> _logger;
    private readonly string _supabaseUrl;
    private readonly string _publishableKey;
    private readonly string _secretKey;

    public SupabaseAuthClient(
        HttpClient httpClient,
        IOptions<SupabaseOptions> options,
        ILogger<SupabaseAuthClient> logger
    )
    {
        _httpClient = httpClient;
        _logger = logger;

        var values = options.Value;

        _supabaseUrl = values.Url.TrimEnd('/');
        _publishableKey = values.PublishableKey;
        _secretKey = values.SecretKey;
    }

    public async Task<RegisterResponse> RegisterAsync(
        string email,
        string password,
        CancellationToken cancellationToken
    )
    {
        using var request = CreateRequest(
            HttpMethod.Post,
            "/auth/v1/signup",
            _publishableKey
        );

        request.Content = JsonContent.Create(new
        {
            email,
            password
        });

        using var response = await _httpClient.SendAsync(
            request,
            cancellationToken
        );

        await EnsureSuccessAsync(response);

        var signupResponse =
            await response.Content.ReadFromJsonAsync<SupabaseSignupResponse>(
                JsonOptions,
                cancellationToken
            );

        if (signupResponse is null)
        {
            throw new InvalidOperationException(
                "Supabase hat keine gültige Registrierungsantwort geliefert."
            );
        }

        var requiresEmailConfirmation =
            string.IsNullOrWhiteSpace(signupResponse.AccessToken);

        // Falls Supabase wegen deaktivierter E-Mail-Bestätigung direkt eine
        // Session erzeugt, wird sie beendet. Der Benutzer soll sich bewusst
        // über den Login-Endpunkt anmelden.
        if (!requiresEmailConfirmation)
        {
            try
            {
                await SignOutAsync(
                    signupResponse.AccessToken!,
                    cancellationToken
                );
            }
            catch (Exception exception)
            {
                _logger.LogWarning(
                    exception,
                    "Die bei der Registrierung erzeugte Session konnte nicht beendet werden."
                );
            }
        }

        return new RegisterResponse(
            requiresEmailConfirmation
                ? "Registrierung erfolgreich. Bitte bestätige deine E-Mail-Adresse."
                : "Registrierung erfolgreich. Du kannst dich jetzt anmelden.",
            requiresEmailConfirmation
        );
    }

    public Task<AuthSessionResponse> LoginAsync(
        string email,
        string password,
        CancellationToken cancellationToken
    )
    {
        return RequestSessionAsync(
            "/auth/v1/token?grant_type=password",
            new Dictionary<string, string>
            {
                ["email"] = email,
                ["password"] = password
            },
            cancellationToken
        );
    }

    public Task<AuthSessionResponse> RefreshAsync(
        string refreshToken,
        CancellationToken cancellationToken
    )
    {
        return RequestSessionAsync(
            "/auth/v1/token?grant_type=refresh_token",
            new Dictionary<string, string>
            {
                ["refresh_token"] = refreshToken
            },
            cancellationToken
        );
    }

    public async Task SignOutAsync(
        string accessToken,
        CancellationToken cancellationToken
    )
    {
        using var request = CreateRequest(
            HttpMethod.Post,
            "/auth/v1/logout?scope=local",
            _publishableKey,
            accessToken
        );

        using var response = await _httpClient.SendAsync(
            request,
            cancellationToken
        );

        await EnsureSuccessAsync(response);
    }

    public async Task<IReadOnlyList<SupabaseDirectoryUser>>
        GetConfirmedUsersAsync(CancellationToken cancellationToken)
    {
        var result = new List<SupabaseDirectoryUser>();
        var page = 1;
        var loadedUserCount = 0;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var path =
                $"/auth/v1/admin/users?page={page}&per_page={UserPageSize}";

            using var request = CreateRequest(
                HttpMethod.Get,
                path,
                _secretKey,
                _secretKey
            );

            using var response = await _httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken
            );

            await EnsureSuccessAsync(response);

            await using var stream =
                await response.Content.ReadAsStreamAsync(cancellationToken);

            var pageResponse =
                await JsonSerializer.DeserializeAsync<SupabaseUsersResponse>(
                    stream,
                    JsonOptions,
                    cancellationToken
                );

            if (pageResponse is null)
            {
                throw new InvalidOperationException(
                    "Supabase hat keine gültige Nutzerantwort geliefert."
                );
            }

            loadedUserCount += pageResponse.Users.Count;

            result.AddRange(
                pageResponse.Users
                    .Where(user =>
                        !string.IsNullOrWhiteSpace(user.Id) &&
                        !string.IsNullOrWhiteSpace(user.Email) &&
                        user.EmailConfirmedAt.HasValue
                    )
                    .Select(user => new SupabaseDirectoryUser(
                        user.Id,
                        user.Email!
                    ))
            );

            if (HasLoadedAllUsers(response, loadedUserCount))
            {
                break;
            }

            if (pageResponse.Users.Count < UserPageSize)
            {
                break;
            }

            page++;
        }

        return result
            .GroupBy(user => user.UserId, StringComparer.Ordinal)
            .Select(group => group.First())
            .ToArray();
    }

    public async Task StorePublicKeyAsync(
    string userId,
    SupabaseStoredPublicKey publicKey,
    CancellationToken cancellationToken
)
{
    using var request = CreateRequest(
        HttpMethod.Put,
        $"/auth/v1/admin/users/{Uri.EscapeDataString(userId)}",
        _secretKey,
        _secretKey
    );

    request.Content = JsonContent.Create(new
    {
        user_metadata = new
        {
            e2ee_public_key = new
            {
                key_id =
                    publicKey.KeyId,
                public_key =
                    publicKey.PublicKey,
                updated_at =
                    publicKey.UpdatedAt
            }
        }
    });

    using var response =
        await _httpClient.SendAsync(
            request,
            cancellationToken
        );

    await EnsureSuccessAsync(response);
}

    public async Task<SupabaseStoredPublicKey?>
        GetPublicKeyAsync(
            string userId,
            CancellationToken cancellationToken
        )
    {
        using var request = CreateRequest(
            HttpMethod.Get,
            $"/auth/v1/admin/users/{Uri.EscapeDataString(userId)}",
            _secretKey,
            _secretKey
        );

        using var response =
            await _httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken
            );

        if (
            response.StatusCode ==
            HttpStatusCode.NotFound
        )
        {
            return null;
        }

        await EnsureSuccessAsync(response);

        var user = await response.Content
            .ReadFromJsonAsync<SupabaseUser>(
                JsonOptions,
                cancellationToken
            );

        if (
            user is null ||
            string.IsNullOrWhiteSpace(user.Id)
        )
        {
            throw new InvalidOperationException(
                "Supabase hat keine gültige Nutzerantwort geliefert."
            );
        }

        var metadata =
            user.UserMetadata?.E2eePublicKey;

        if (metadata is null)
        {
            return null;
        }

        return new SupabaseStoredPublicKey(
            metadata.KeyId ?? string.Empty,
            metadata.PublicKey ?? string.Empty,
            metadata.UpdatedAt ?? DateTimeOffset.MinValue
        );
    }

    private async Task<AuthSessionResponse> RequestSessionAsync(
        string path,
        Dictionary<string, string> body,
        CancellationToken cancellationToken
    )
    {
        using var request = CreateRequest(
            HttpMethod.Post,
            path,
            _publishableKey
        );

        request.Content = JsonContent.Create(body);

        using var response = await _httpClient.SendAsync(
            request,
            cancellationToken
        );

        await EnsureSuccessAsync(response);

        var session =
            await response.Content.ReadFromJsonAsync<SupabaseSessionResponse>(
                JsonOptions,
                cancellationToken
            );

        if (session is null ||
            string.IsNullOrWhiteSpace(session.AccessToken) ||
            string.IsNullOrWhiteSpace(session.RefreshToken) ||
            session.User is null ||
            string.IsNullOrWhiteSpace(session.User.Id) ||
            string.IsNullOrWhiteSpace(session.User.Email))
        {
            throw new InvalidOperationException(
                "Supabase hat keine gültige Session geliefert."
            );
        }

        var expiresAt = session.ExpiresAt
            ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            + session.ExpiresIn.GetValueOrDefault(3600);

        return new AuthSessionResponse(
            session.AccessToken,
            session.RefreshToken,
            expiresAt,
            new AuthenticatedUserResponse(
                session.User.Id,
                session.User.Email
            )
        );
    }

    private HttpRequestMessage CreateRequest(
        HttpMethod method,
        string path,
        string apiKey,
        string? bearerToken = null
    )
    {
        var request = new HttpRequestMessage(
            method,
            $"{_supabaseUrl}{path}"
        );

        request.Headers.TryAddWithoutValidation("apikey", apiKey);
        request.Headers.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/json")
        );

        if (!string.IsNullOrWhiteSpace(bearerToken))
        {
            request.Headers.Authorization =
                new AuthenticationHeaderValue(
                    "Bearer",
                    bearerToken
                );
        }

        return request;
    }

    private static Task EnsureSuccessAsync(
        HttpResponseMessage response
    )
    {
        if (!response.IsSuccessStatusCode)
        {
            throw new SupabaseApiException(response.StatusCode);
        }

        return Task.CompletedTask;
    }

    private static bool HasLoadedAllUsers(
        HttpResponseMessage response,
        int loadedUserCount
    )
    {
        if (!response.Headers.TryGetValues(
                "X-Total-Count",
                out var values
            ))
        {
            return false;
        }

        return int.TryParse(
                values.FirstOrDefault(),
                out var totalUserCount
            ) &&
            loadedUserCount >= totalUserCount;
    }

    private sealed class SupabaseSignupResponse
    {
        [JsonPropertyName("access_token")]
        public string? AccessToken { get; init; }
    }

    private sealed class SupabaseSessionResponse
    {
        [JsonPropertyName("access_token")]
        public string AccessToken { get; init; } = string.Empty;

        [JsonPropertyName("refresh_token")]
        public string RefreshToken { get; init; } = string.Empty;

        [JsonPropertyName("expires_in")]
        public int? ExpiresIn { get; init; }

        [JsonPropertyName("expires_at")]
        public long? ExpiresAt { get; init; }

        [JsonPropertyName("user")]
        public SupabaseUser? User { get; init; }
    }

    private sealed class SupabaseUsersResponse
    {
        [JsonPropertyName("users")]
        public List<SupabaseUser> Users { get; init; } = new();
    }

    private sealed class SupabaseUser
    {
        [JsonPropertyName("id")]
        public string Id { get; init; } = string.Empty;

        [JsonPropertyName("email")]
        public string? Email { get; init; }

        [JsonPropertyName("email_confirmed_at")]
        public DateTimeOffset? EmailConfirmedAt { get; init; }

        [JsonPropertyName("user_metadata")]
        public SupabaseUserMetadata? UserMetadata { get; init; }
    }

    private sealed class SupabaseUserMetadata
    {
        [JsonPropertyName("e2ee_public_key")]
        public SupabasePublicKeyMetadata?
            E2eePublicKey { get; init; }
    }

    private sealed class SupabasePublicKeyMetadata
    {
        [JsonPropertyName("key_id")]
        public string? KeyId { get; init; }

        [JsonPropertyName("public_key")]
        public string? PublicKey {
            get;
            init;
        }

        [JsonPropertyName("updated_at")]
        public DateTimeOffset? UpdatedAt {
            get;
            init;
        }
    }
}
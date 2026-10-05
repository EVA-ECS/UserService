using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using UserService.Configuration;
using UserService.Services;
using Xunit;

namespace UserService.Tests;

public sealed class SupabaseAuthClientTests
{
    private sealed class Handler(Func<HttpRequestMessage, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => send(request);
    }
    private static SupabaseAuthClient Client(Func<HttpRequestMessage, Task<HttpResponseMessage>> send) => new(
        new HttpClient(new Handler(send)), Options.Create(new SupabaseOptions
        { Url = "https://example.invalid/", PublishableKey = "fake-publishable", SecretKey = "fake-backend" }),
        NullLogger<SupabaseAuthClient>.Instance);
    private static HttpResponseMessage Json(string text, HttpStatusCode status = HttpStatusCode.OK) => new(status)
    { Content = new StringContent(text, System.Text.Encoding.UTF8, "application/json") };

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task LoginAndRefreshUseCorrectGrantHeadersAndMapSession(bool refresh)
    {
        var client = Client(async request =>
        {
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal("fake-publishable", Assert.Single(request.Headers.GetValues("apikey")));
            Assert.Null(request.Headers.Authorization);
            Assert.Equal(refresh ? "?grant_type=refresh_token" : "?grant_type=password", request.RequestUri!.Query);
            using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync());
            Assert.Equal(refresh ? "refresh" : "alice@example.test", body.RootElement.GetProperty(refresh ? "refresh_token" : "email").GetString());
            return Json("{\"access_token\":\"access\",\"refresh_token\":\"refresh\",\"expires_at\":12345,\"user\":{\"id\":\"alice\",\"email\":\"alice@example.test\"}}");
        });
        var result = refresh ? await client.RefreshAsync("refresh", default) : await client.LoginAsync("alice@example.test", "password", default);
        Assert.Equal("access", result.AccessToken);
        Assert.Equal("refresh", result.RefreshToken);
        Assert.Equal(12345, result.ExpiresAt);
        Assert.Equal("alice", result.User.UserId);
    }

    [Theory]
    [InlineData("null")] [InlineData("{}")] [InlineData("{\"access_token\":\"a\"}")]
    [InlineData("{\"access_token\":\"a\",\"refresh_token\":\"r\"}")]
    [InlineData("{\"access_token\":\"a\",\"refresh_token\":\"r\",\"user\":{}}")]
    [InlineData("{\"access_token\":\"a\",\"refresh_token\":\"r\",\"user\":{\"id\":\"alice\"}}")]
    public async Task IncompleteSessionsAreRejected(string json) =>
        await Assert.ThrowsAsync<InvalidOperationException>(() => Client(_ => Task.FromResult(Json(json))).LoginAsync("email", "password", default));

    [Theory]
    [InlineData(null, 3600)] [InlineData(120, 120)]
    public async Task SessionExpiryFallsBackToRelativeLifetime(int? expiry, int expected)
    {
        var started = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var json = JsonSerializer.Serialize(new { access_token = "access", refresh_token = "refresh", expires_in = expiry, user = new { id = "alice", email = "alice@example.test" } });
        var result = await Client(_ => Task.FromResult(Json(json))).LoginAsync("email", "password", default);
        Assert.InRange(result.ExpiresAt, started + expected, DateTimeOffset.UtcNow.ToUnixTimeSeconds() + expected);
    }

    [Theory]
    [InlineData(false, false)] [InlineData(true, false)] [InlineData(true, true)]
    public async Task RegistrationRequiresConfirmationOrSignsOutAnAutomaticallyCreatedSession(bool session, bool logoutFails)
    {
        var calls = new List<string>();
        var client = Client(async request =>
        {
            calls.Add(request.RequestUri!.AbsolutePath);
            if (calls.Count == 1)
            {
                Assert.Equal("/auth/v1/signup", request.RequestUri.AbsolutePath);
                using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync());
                Assert.Equal("password", body.RootElement.GetProperty("password").GetString());
                return Json(session ? "{\"access_token\":\"temporary\"}" : "{}");
            }
            Assert.Equal("/auth/v1/logout", request.RequestUri.AbsolutePath);
            Assert.Equal("?scope=local", request.RequestUri.Query);
            Assert.Equal("temporary", request.Headers.Authorization!.Parameter);
            return Json("{}", logoutFails ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK);
        });
        var result = await client.RegisterAsync("email", "password", default);
        Assert.Equal(!session, result.RequiresEmailConfirmation);
        Assert.Equal(session ? 2 : 1, calls.Count);
    }

    [Fact]
    public async Task NullSignupAndHttpFailuresAreRejected()
    {
        await Assert.ThrowsAsync<InvalidOperationException>(() => Client(_ => Task.FromResult(Json("null"))).RegisterAsync("email", "password", default));
        var error = await Assert.ThrowsAsync<SupabaseApiException>(() => Client(_ => Task.FromResult(Json("{}", HttpStatusCode.Unauthorized))).LoginAsync("email", "password", default));
        Assert.Equal(HttpStatusCode.Unauthorized, error.StatusCode);
    }

    [Fact]
    public async Task DirectoryFiltersUnconfirmedInvalidUsersAndDeduplicatesAcrossPages()
    {
        var count = 0;
        var client = Client(request =>
        {
            count++;
            Assert.Equal("fake-backend", request.Headers.Authorization!.Parameter);
            Assert.Equal("fake-backend", Assert.Single(request.Headers.GetValues("apikey")));
            Assert.Contains("per_page=1000", request.RequestUri!.Query);
            var confirmed = "2026-09-01T12:00:00Z";
            object[] users = count == 1
                ? Enumerable.Range(0, 1000).Select(i => (object)new { id = i < 2 ? "alice" : i.ToString(), email = i == 2 ? "" : "alice@example.test", email_confirmed_at = i < 3 ? confirmed : null }).ToArray()
                : [new { id = "bob", email = "bob@example.test", email_confirmed_at = confirmed }, new { id = "", email = "invalid@example.test", email_confirmed_at = confirmed }];
            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonContent.Create(new { users }) };
            response.Headers.Add("X-Total-Count", "1002");
            return Task.FromResult(response);
        });
        var users = await client.GetConfirmedUsersAsync(default);
        Assert.Equal(new[] { "alice", "bob" }, users.Select(x => x.UserId));
        Assert.Equal(2, count);
    }

    [Theory]
    [InlineData(null)] [InlineData("not-a-number")]
    public async Task DirectoryStopsOnShortPageWithoutUsableTotalCount(string? total)
    {
        var client = Client(_ =>
        {
            var response = Json("{\"users\":[]}");
            if (total is not null) response.Headers.Add("X-Total-Count", total);
            return Task.FromResult(response);
        });
        Assert.Empty(await client.GetConfirmedUsersAsync(default));
        await Assert.ThrowsAsync<InvalidOperationException>(() => Client(_ => Task.FromResult(Json("null"))).GetConfirmedUsersAsync(default));
    }

    [Fact]
    public async Task PublicKeyStorageUsesAdminCredentialsEscapesUserIdAndPreservesMetadata()
    {
        var timestamp = DateTimeOffset.UtcNow;
        var client = Client(async request =>
        {
            Assert.Equal(HttpMethod.Put, request.Method);
            Assert.EndsWith("alice%2Fother", request.RequestUri!.AbsolutePath);
            Assert.Equal("fake-backend", request.Headers.Authorization!.Parameter);
            using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync());
            var key = body.RootElement.GetProperty("user_metadata").GetProperty("e2ee_public_key");
            Assert.Equal("fingerprint", key.GetProperty("key_id").GetString());
            Assert.Equal("encoded", key.GetProperty("public_key").GetString());
            Assert.Equal(timestamp, key.GetProperty("updated_at").GetDateTimeOffset());
            return Json("{}");
        });
        await client.StorePublicKeyAsync("alice/other", new("fingerprint", "encoded", timestamp), default);
    }

    [Theory]
    [InlineData(404, "{}")] [InlineData(200, "{\"id\":\"alice\"}")]
    public async Task MissingPublicKeyReturnsNull(int status, string json) =>
        Assert.Null(await Client(_ => Task.FromResult(Json(json, (HttpStatusCode)status))).GetPublicKeyAsync("alice", default));

    [Theory]
    [InlineData("null")] [InlineData("{}")]
    public async Task InvalidUserResponsesAreRejected(string json) =>
        await Assert.ThrowsAsync<InvalidOperationException>(() => Client(_ => Task.FromResult(Json(json))).GetPublicKeyAsync("alice", default));

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task PublicKeyMetadataIsMappedIncludingMissingMetadataFields(bool missing)
    {
        var json = missing ? "{\"id\":\"alice\",\"user_metadata\":{\"e2ee_public_key\":{}}}"
            : "{\"id\":\"alice\",\"user_metadata\":{\"e2ee_public_key\":{\"key_id\":\"fingerprint\",\"public_key\":\"encoded\",\"updated_at\":\"2026-09-01T12:00:00Z\"}}}";
        var key = await Client(_ => Task.FromResult(Json(json))).GetPublicKeyAsync("alice", default);
        Assert.Equal(missing ? "" : "fingerprint", key!.KeyId);
        Assert.Equal(missing ? "" : "encoded", key.PublicKey);
        Assert.Equal(missing ? DateTimeOffset.MinValue : DateTimeOffset.Parse("2026-09-01T12:00:00Z"), key.UpdatedAt);
    }
}

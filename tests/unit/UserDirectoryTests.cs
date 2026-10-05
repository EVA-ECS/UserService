using System.Security.Cryptography;
using Moq;
using StackExchange.Redis;
using UserService.Models;
using UserService.Services;
using Xunit;

namespace UserService.Tests;

public sealed class UserDirectoryTests
{
    private static UserDirectoryService Service(Mock<ISupabaseAuthClient> auth, Mock<IDatabase>? database = null)
    {
        var redis = new Mock<IConnectionMultiplexer>();
        redis.Setup(x => x.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Returns((database ?? new()).Object);
        return new(auth.Object, redis.Object);
    }

    [Fact]
    public async Task DirectoryExcludesCurrentUserSortsNamesAndReadsPresence()
    {
        var auth = new Mock<ISupabaseAuthClient>();
        auth.Setup(x => x.GetConfirmedUsersAsync(default)).ReturnsAsync([new("self", "Self"), new("b", "zulu"), new("a", "Alpha")]);
        var database = new Mock<IDatabase>();
        database.Setup(x => x.KeyExistsAsync((RedisKey)"eva-chat:online:a", It.IsAny<CommandFlags>())).ReturnsAsync(true);
        var users = await Service(auth, database).GetUsersAsync("self", default);
        Assert.Equal(new[] { "a", "b" }, users.Select(x => x.UserId));
        Assert.True(users[0].IsOnline);
        Assert.False(users[1].IsOnline);
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        auth.Setup(x => x.GetConfirmedUsersAsync(cancellation.Token)).ReturnsAsync([new("a", "Alpha")]);
        await Assert.ThrowsAsync<OperationCanceledException>(() => Service(auth).GetUsersAsync("self", cancellation.Token));
    }

    [Fact]
    public async Task PublishedKeyHasCanonicalEncodingFingerprintAndTimestamp()
    {
        using var key = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var bytes = key.ExportSubjectPublicKeyInfo();
        var encoded = Encode(bytes);
        var auth = new Mock<ISupabaseAuthClient>();
        SupabaseStoredPublicKey? stored = null;
        auth.Setup(x => x.StorePublicKeyAsync("alice", It.IsAny<SupabaseStoredPublicKey>(), default))
            .Callback<string, SupabaseStoredPublicKey, CancellationToken>((_, value, _) => stored = value).Returns(Task.CompletedTask);
        var result = await Service(auth).PublishPublicKeyAsync("alice", new() { PublicKey = encoded }, default);
        Assert.Equal(encoded, result.PublicKey);
        Assert.Equal("sha256:" + Encode(SHA256.HashData(bytes)), result.KeyId);
        Assert.Equal(result.KeyId, stored!.KeyId);
        Assert.InRange(result.UpdatedAt, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow);
        auth.Setup(x => x.GetPublicKeyAsync("alice", default)).ReturnsAsync(stored);
        Assert.Equal(result, await Service(auth).GetPublicKeyAsync("alice", default));
    }

    [Theory]
    [InlineData("")] [InlineData(" ")] [InlineData("A")] [InlineData("bad+key=")] [InlineData("abcd")]
    public async Task InvalidKeysAreRejectedBeforeSaving(string encoded)
    {
        var auth = new Mock<ISupabaseAuthClient>(MockBehavior.Strict);
        await Assert.ThrowsAsync<ArgumentException>(() => Service(auth).PublishPublicKeyAsync("alice", new() { PublicKey = encoded }, default));
    }

    [Fact]
    public async Task ExcessivelyLongKeysWrongCurveAndTrailingBytesAreRejected()
    {
        var service = Service(new());
        await Assert.ThrowsAsync<ArgumentException>(() => service.PublishPublicKeyAsync("alice", new() { PublicKey = new string('a', 513) }, default));
        using var wrong = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384);
        await Assert.ThrowsAsync<ArgumentException>(() => service.PublishPublicKeyAsync("alice", new() { PublicKey = Encode(wrong.ExportSubjectPublicKeyInfo()) }, default));
        using var valid = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        await Assert.ThrowsAsync<ArgumentException>(() => service.PublishPublicKeyAsync("alice", new() { PublicKey = Encode([.. valid.ExportSubjectPublicKeyInfo(), 0]) }, default));
    }

    [Fact]
    public async Task AbsentKeysReturnNullAndCorruptStoredMetadataIsRejected()
    {
        var auth = new Mock<ISupabaseAuthClient>();
        Assert.Null(await Service(auth).GetPublicKeyAsync("alice", default));
        using var key = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var encoded = Encode(key.ExportSubjectPublicKeyInfo());
        auth.Setup(x => x.GetPublicKeyAsync("alice", default)).ReturnsAsync(new SupabaseStoredPublicKey("wrong-fingerprint", encoded, DateTimeOffset.UtcNow));
        await Assert.ThrowsAsync<InvalidOperationException>(() => Service(auth).GetPublicKeyAsync("alice", default));
        auth.Setup(x => x.GetPublicKeyAsync("alice", default)).ReturnsAsync(new SupabaseStoredPublicKey("sha256:" + Encode(SHA256.HashData(key.ExportSubjectPublicKeyInfo())), encoded, DateTimeOffset.MinValue));
        await Assert.ThrowsAsync<InvalidOperationException>(() => Service(auth).GetPublicKeyAsync("alice", default));
    }

    private static string Encode(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

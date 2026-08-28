using StackExchange.Redis;
using UserService.Models;

namespace UserService.Services;

public sealed class UserDirectoryService : IUserDirectoryService
{
    private readonly ISupabaseAuthClient _supabase;
    private readonly IDatabase _redis;

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

    private static string GetOnlineKey(string userId)
    {
        return $"eva-chat:online:{userId}";
    }
}
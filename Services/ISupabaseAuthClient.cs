using UserService.Models;

namespace UserService.Services;

public interface ISupabaseAuthClient
{
    Task<RegisterResponse> RegisterAsync(
        string email,
        string password,
        CancellationToken cancellationToken
    );

    Task<AuthSessionResponse> LoginAsync(
        string email,
        string password,
        CancellationToken cancellationToken
    );

    Task<AuthSessionResponse> RefreshAsync(
        string refreshToken,
        CancellationToken cancellationToken
    );

    Task SignOutAsync(
        string accessToken,
        CancellationToken cancellationToken
    );

    Task<IReadOnlyList<SupabaseDirectoryUser>> GetConfirmedUsersAsync(
        CancellationToken cancellationToken
    );

    Task StorePublicKeyAsync(
        string userId,
        SupabaseStoredPublicKey publicKey,
        CancellationToken cancellationToken
    );

    Task<SupabaseStoredPublicKey?> GetPublicKeyAsync(
        string userId,
        CancellationToken cancellationToken
    );
}
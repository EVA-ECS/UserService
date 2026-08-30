using UserService.Models;

namespace UserService.Services;

public interface IUserDirectoryService
{
    Task<IReadOnlyList<UserDirectoryEntryResponse>> GetUsersAsync(
        string currentUserId,
        CancellationToken cancellationToken
    );

    Task<PublicKeyResponse>
    PublishPublicKeyAsync(
        string currentUserId,
        PublishPublicKeyRequest request,
        CancellationToken cancellationToken
    );

    Task<PublicKeyResponse?>
    GetPublicKeyAsync(
        string userId,
        CancellationToken cancellationToken
    );
}
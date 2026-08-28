using System.ComponentModel.DataAnnotations;

namespace UserService.Models;

public sealed record RegisterRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; init; } = string.Empty;

    [Required]
    [MinLength(6)]
    public string Password { get; init; } = string.Empty;
}

public sealed record RegisterResponse(
    string Message,
    bool RequiresEmailConfirmation
);

public sealed record LoginRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; init; } = string.Empty;

    [Required]
    public string Password { get; init; } = string.Empty;
}

public sealed record RefreshRequest
{
    [Required]
    public string RefreshToken { get; init; } = string.Empty;
}

public sealed record AuthenticatedUserResponse(
    string UserId,
    string Email
);

public sealed record AuthSessionResponse(
    string AccessToken,
    string RefreshToken,
    long ExpiresAt,
    AuthenticatedUserResponse User
);

public sealed record UserDirectoryEntryResponse(
    string UserId,
    string DisplayName,
    bool IsOnline
);

public sealed record ApiErrorResponse(
    string Code,
    string Message
);

public sealed record SupabaseDirectoryUser(
    string UserId,
    string Email
);
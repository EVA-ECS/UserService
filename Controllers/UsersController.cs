using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using UserService.Models;
using UserService.Services;

namespace UserService.Controllers;

[ApiController]
[Route("api/users")]
[Authorize]
public sealed class UsersController : ControllerBase
{
    private readonly IUserDirectoryService _directory;
    private readonly ILogger<UsersController> _logger;

    public UsersController(
        IUserDirectoryService directory,
        ILogger<UsersController> logger
    )
    {
        _directory = directory;
        _logger = logger;
    }

    [HttpGet]
    public async Task<ActionResult<
        IReadOnlyList<UserDirectoryEntryResponse>>> GetUsers(
        CancellationToken cancellationToken
    )
    {
        var currentUserId =
            User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;

        if (string.IsNullOrWhiteSpace(currentUserId))
        {
            return Unauthorized();
        }

        try
        {
            var users = await _directory.GetUsersAsync(
                currentUserId,
                cancellationToken
            );

            return Ok(users);
        }
        catch (Exception exception)
            when (exception is not OperationCanceledException)
        {
            _logger.LogError(
                exception,
                "Die Nutzerliste konnte nicht geladen werden."
            );

            return StatusCode(
                StatusCodes.Status503ServiceUnavailable,
                new ApiErrorResponse(
                    "user_directory_unavailable",
                    "Die Nutzerliste ist momentan nicht verfügbar."
                )
            );
        }
    }
}
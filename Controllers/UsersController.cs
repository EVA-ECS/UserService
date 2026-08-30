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

    [HttpPut("me/public-key")]
    public async Task<ActionResult<PublicKeyResponse>>
        PublishPublicKey(
            [FromBody]
                PublishPublicKeyRequest request,
            CancellationToken cancellationToken
        )
    {
        var currentUserId =
            User.FindFirst(
                ClaimTypes.NameIdentifier
            )?.Value
            ?? User.FindFirst("sub")?.Value;

        if (
            string.IsNullOrWhiteSpace(
                currentUserId
            )
        )
        {
            return Unauthorized();
        }

        try
        {
            var result =
                await _directory
                    .PublishPublicKeyAsync(
                        currentUserId,
                        request,
                        cancellationToken
                    );

            return Ok(result);
        }
        catch (ArgumentException exception)
        {
            return BadRequest(
                new ApiErrorResponse(
                    "invalid_public_key",
                    exception.Message
                )
            );
        }
        catch (Exception exception)
            when (
                exception
                    is not OperationCanceledException
            )
        {
            _logger.LogError(
                exception,
                "Der Public Key konnte nicht gespeichert werden."
            );

            return StatusCode(
                StatusCodes
                    .Status503ServiceUnavailable,
                new ApiErrorResponse(
                    "public_key_service_unavailable",
                    "Der Public Key konnte momentan nicht gespeichert werden."
                )
            );
        }
    }

    [HttpGet("{userId:guid}/public-key")]
    public async Task<ActionResult<PublicKeyResponse>>
        GetPublicKey(
            Guid userId,
            CancellationToken cancellationToken
        )
    {
        try
        {
            var result =
                await _directory
                    .GetPublicKeyAsync(
                        userId.ToString(),
                        cancellationToken
                    );

            if (result is null)
            {
                return NotFound(
                    new ApiErrorResponse(
                        "public_key_not_found",
                        "Für diesen Nutzer wurde noch kein Public Key veröffentlicht."
                    )
                );
            }

            return Ok(result);
        }
        catch (Exception exception)
            when (
                exception
                    is not OperationCanceledException
            )
        {
            _logger.LogError(
                exception,
                "Der Public Key konnte nicht geladen werden."
            );

            return StatusCode(
                StatusCodes
                    .Status503ServiceUnavailable,
                new ApiErrorResponse(
                    "public_key_service_unavailable",
                    "Der Public Key konnte momentan nicht geladen werden."
                )
            );
        }
    }
}
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using UserService.Models;
using UserService.Services;

namespace UserService.Controllers;

[ApiController]
[Route("api/auth")]
public sealed class AuthController : ControllerBase
{
    private readonly ISupabaseAuthClient _supabase;
    private readonly ILogger<AuthController> _logger;

    public AuthController(
        ISupabaseAuthClient supabase,
        ILogger<AuthController> logger
    )
    {
        _supabase = supabase;
        _logger = logger;
    }

    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<ActionResult<RegisterResponse>> Register(
        [FromBody] RegisterRequest request,
        CancellationToken cancellationToken
    )
    {
        try
        {
            var result = await _supabase.RegisterAsync(
                request.Email.Trim().ToLowerInvariant(),
                request.Password,
                cancellationToken
            );

            return Ok(result);
        }
        catch (SupabaseApiException exception)
        {
            _logger.LogWarning(
                "Supabase-Registrierung fehlgeschlagen: HTTP {StatusCode}.",
                (int)exception.StatusCode
            );

            if ((int)exception.StatusCode >= 500)
            {
                return UpstreamUnavailable();
            }

            return BadRequest(new ApiErrorResponse(
                "registration_failed",
                "Die Registrierung konnte nicht abgeschlossen werden."
            ));
        }
        catch (Exception exception)
            when (exception is not OperationCanceledException)
        {
            _logger.LogError(
                exception,
                "Die Registrierung ist unerwartet fehlgeschlagen."
            );

            return UpstreamUnavailable();
        }
    }

    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<ActionResult<AuthSessionResponse>> Login(
        [FromBody] LoginRequest request,
        CancellationToken cancellationToken
    )
    {
        try
        {
            var session = await _supabase.LoginAsync(
                request.Email.Trim().ToLowerInvariant(),
                request.Password,
                cancellationToken
            );

            return Ok(session);
        }
        catch (SupabaseApiException exception)
        {
            _logger.LogWarning(
                "Supabase-Login fehlgeschlagen: HTTP {StatusCode}.",
                (int)exception.StatusCode
            );

            if ((int)exception.StatusCode >= 500)
            {
                return UpstreamUnavailable();
            }

            return Unauthorized(new ApiErrorResponse(
                "invalid_credentials",
                "E-Mail-Adresse oder Passwort ist falsch."
            ));
        }
        catch (Exception exception)
            when (exception is not OperationCanceledException)
        {
            _logger.LogError(
                exception,
                "Der Login ist unerwartet fehlgeschlagen."
            );

            return UpstreamUnavailable();
        }
    }

    [HttpPost("refresh")]
    [AllowAnonymous]
    public async Task<ActionResult<AuthSessionResponse>> Refresh(
        [FromBody] RefreshRequest request,
        CancellationToken cancellationToken
    )
    {
        try
        {
            var session = await _supabase.RefreshAsync(
                request.RefreshToken,
                cancellationToken
            );

            return Ok(session);
        }
        catch (SupabaseApiException exception)
        {
            _logger.LogWarning(
                "Supabase-Refresh fehlgeschlagen: HTTP {StatusCode}.",
                (int)exception.StatusCode
            );

            if ((int)exception.StatusCode >= 500)
            {
                return UpstreamUnavailable();
            }

            return Unauthorized(new ApiErrorResponse(
                "invalid_refresh_token",
                "Die Sitzung ist abgelaufen. Bitte melde dich erneut an."
            ));
        }
        catch (Exception exception)
            when (exception is not OperationCanceledException)
        {
            _logger.LogError(
                exception,
                "Die Session-Erneuerung ist unerwartet fehlgeschlagen."
            );

            return UpstreamUnavailable();
        }
    }

    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout(
        CancellationToken cancellationToken
    )
    {
        var authorization = Request.Headers.Authorization.ToString();

        if (!authorization.StartsWith(
                "Bearer ",
                StringComparison.OrdinalIgnoreCase
            ))
        {
            return Unauthorized();
        }

        var accessToken = authorization["Bearer ".Length..].Trim();

        try
        {
            await _supabase.SignOutAsync(
                accessToken,
                cancellationToken
            );

            return NoContent();
        }
        catch (SupabaseApiException exception)
        {
            _logger.LogWarning(
                "Supabase-Logout fehlgeschlagen: HTTP {StatusCode}.",
                (int)exception.StatusCode
            );

            return UpstreamUnavailable();
        }
        catch (Exception exception)
            when (exception is not OperationCanceledException)
        {
            _logger.LogError(
                exception,
                "Der Logout ist unerwartet fehlgeschlagen."
            );

            return UpstreamUnavailable();
        }
    }

    private ObjectResult UpstreamUnavailable()
    {
        return StatusCode(
            StatusCodes.Status503ServiceUnavailable,
            new ApiErrorResponse(
                "authentication_service_unavailable",
                "Der Anmeldedienst ist momentan nicht verfügbar."
            )
        );
    }
}
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace UserService.Controllers;

[ApiController]
public sealed class HealthController : ControllerBase
{
    [HttpGet("/health")]
    [AllowAnonymous]
    public IActionResult Health()
    {
        return Ok(new
        {
            Status = "Healthy",
            Service = "UserService",
            Timestamp = DateTimeOffset.UtcNow
        });
    }
}
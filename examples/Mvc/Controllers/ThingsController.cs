using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Nine.AspNetCore;

namespace Mvc.Controllers;

// GET /api/things with "Authorization: Bearer <9in access token>" that has the read:things scope.
[ApiController]
[Route("api/things")]
[RequireScope("read:things")]
public sealed class ThingsController : ControllerBase
{
    [HttpGet]
    public IActionResult Get() => Ok(new { user = User.FindFirstValue("sub"), scopes = User.GetScopes() });

    [HttpPost]
    [RequireScope("write:things")] // both read:things and write:things
    public IActionResult Create() => Created("/api/things/1", new { id = 1 });
}

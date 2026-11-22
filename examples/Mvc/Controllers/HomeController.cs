using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Nine.AspNetCore;

namespace Mvc.Controllers;

public sealed class HomeController : Controller
{
    public IActionResult Index() => View();

    // Signed-out visitors go to the 9in sign-in page and come back here.
    [Authorize]
    public async Task<IActionResult> Profile()
    {
        ViewData["AccessToken"] = await HttpContext.GetNineAccessTokenAsync() is { } token ? token[..12] + "…" : null;
        return View();
    }
}

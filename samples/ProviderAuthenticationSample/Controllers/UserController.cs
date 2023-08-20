using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ProviderAuthenticationSample.Controllers;

[ApiController]
[Route("[controller]")]
public class UserController : ControllerBase
{
    public UserController() { }

    [HttpGet]
    public IActionResult Get()
    {
        var user = HttpContext.User;

        return Ok($"Get sucess with user: {user.Identity?.Name}");
    }

    [AllowAnonymous]
    [HttpGet("public-method")]
    public IActionResult PublicMethod()
    {
        return Ok("Get sucess as anonymous");
    }
}

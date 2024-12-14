using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Web.Resource;

namespace MultiAuthenticationSample.Controllers;

/// <summary>
/// Controller responsible for managing user-related actions with various authentication policies.
/// </summary>
[ApiController]
[Route("[controller]")]
public class UserController : ControllerBase
{
    public UserController() { }

    // Helper method to retrieve the user's name from the HttpContext.
    private string GetUserName()
    {
        var user = HttpContext.User;
        return user.Identity?.Name ?? "Unknown";
    }

    // Action method for default policy - no specific authorization policy required.
    [HttpGet]
    public IActionResult DefaultPolicy()
    {
        return Ok($"Get success with user: {GetUserName()}");
    }

    // Action method requiring "apiKeyPolicy" authorization policy.
    [Authorize(Policy = "apiKeyPolicy")]
    [HttpGet("api-key")]
    public IActionResult ApiKeyPolicy()
    {
        return Ok($"Get success with user: {GetUserName()}");
    }

    // Action method requiring "jwtPolicy" authorization policy.
    [Authorize(Policy = "jwtPolicy")]
    [HttpGet("jwt")]
    public IActionResult JwtPolicy()
    {
        return Ok($"Get success with user: {GetUserName()}");
    }

    // Action method requiring "msalPolicy" authorization policy.
    [Authorize(Policy = "msalPolicy")]
    [HttpGet("msal")]
    public IActionResult MsalPolicy()
    {
        return Ok($"Get success with user: {GetUserName()}");
    }

    // Action method requiring "anyAuthPolicy" authorization policy.
    [Authorize(Policy = "anyAuthPolicy")]
    [HttpGet("any")]
    public IActionResult PolicyAny()
    {
        return Ok($"Get success with user: {GetUserName()}");
    }

    // Action method requiring specific authentication schemes and scope requirements.
    [Authorize(AuthenticationSchemes = "Bearer,ApiKey")]
    [RequiredScope("Admin", "CiperKeyApi")]
    [HttpGet("scheme-scope")]
    public IActionResult SchemeAndScope()
    {
        return Ok($"Get success with user: {GetUserName()}");
    }

    // Action method demonstrating a CORS-restricted endpoint.
    [HttpPost("denied-by-cors")]
    public IActionResult DenyByCors()
    {
        return NoContent();
    }

    // Public action method.
    [AllowAnonymous]
    [HttpGet("public-method")]
    public IActionResult PublicMethod()
    {
        return Ok("Get sucess as anonymous");
    }

    // Action method requiring "msalPolicy" authorization policy and role "Manager".
    [Authorize(Policy = "msalPolicy", Roles = "Manager")]
    [HttpGet("msal-role")]
    public IActionResult MsalPolicyWithRole()
    {
        return Ok($"Get success with user: {GetUserName()}");
    }
}

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Microsoft.Identity.Web.Resource;

/// <summary>
/// Specifies that the current user must have the specified permission(s) to access the resource.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class RequiredPermissionAttribute : Attribute, IAuthorizationFilter
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RequiredPermissionAttribute"/> class with the accepted permissions.
    /// </summary>
    /// <param name="acceptedPermissions">The accepted permissions that the user must have.</param>
    public RequiredPermissionAttribute(params string[] acceptedPermissions)
    {
        Permissions = acceptedPermissions;
    }

    /// <summary>
    /// Gets or sets the accepted permissions that the user must have.
    /// </summary>
    public string[] Permissions { get; set; }

    /// <inheritdoc/>
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        var user = context.HttpContext.User;

        if (user.Identity is null || !user.Identity.IsAuthenticated)
        {
            context.Result = new UnauthorizedResult();
            return;
        }

        if (Permissions is not null && Permissions.Length > 0)
        {
            var requiredPermissions = new HashSet<string>(Permissions, StringComparer.OrdinalIgnoreCase);
            var userPermissions = new HashSet<string>(context.HttpContext.User.Claims
                .Where(claim => claim.Type.Equals("permission", StringComparison.OrdinalIgnoreCase))
                .Select(claim => claim.Value));

            if (!requiredPermissions.Overlaps(userPermissions))
            {
                context.Result = new ForbidResult();
            }
        }
    }
}

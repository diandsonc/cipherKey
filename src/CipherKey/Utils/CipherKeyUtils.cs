using System.Security.Claims;
using Microsoft.Identity.Web;

namespace CipherKey.Utils
{
    /// <summary>
    /// Utility class.
    /// </summary>
    public static partial class CipherKeyUtils
    {
        /// <summary>
        /// Builds Claims Principal from the provided information. 
        /// The <paramref name="ownerName"/> will be added as claim of type <see cref="ClaimTypes.NameIdentifier"/>.
        /// The <paramref name="ownerName"/> will be added as claim of type <see cref="ClaimTypes.Name"/>.
        /// </summary>
        /// <param name="ownerName">The owner name.</param>
        /// <param name="schemeName">The scheme name.</param>
        /// <param name="claimsIssuer">The claims issuer.</param>
        /// <param name="scope">The token scope.</param>
        /// <returns></returns>
        internal static ClaimsPrincipal BuildPrincipal(string? ownerName, string? schemeName, string claimsIssuer,
            string? scope)
        {
            if (string.IsNullOrWhiteSpace(schemeName))
            {
                throw new ArgumentNullException(nameof(schemeName));
            }

            var identity = new ClaimsIdentity(schemeName);

            if (!string.IsNullOrWhiteSpace(ownerName))
            {
                identity.AddClaims(new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, ownerName, ClaimValueTypes.String, claimsIssuer),
                    new Claim(ClaimTypes.Name, ownerName, ClaimValueTypes.String, claimsIssuer)
                });
            }

            if (!string.IsNullOrEmpty(scope))
            {
                identity.AddClaim(new Claim(ClaimConstants.Scp, scope, ClaimValueTypes.String, claimsIssuer));
            }

            return new ClaimsPrincipal(identity);
        }
    }
}

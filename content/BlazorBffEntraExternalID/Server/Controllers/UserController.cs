using BlazorBffEntraExternalID.Shared.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace BlazorBffEntraExternalID.Server.Controllers;


[Route("api/[controller]")]
[ApiController]
public class UserController : ControllerBase
{
    [HttpGet]
    [AllowAnonymous]
    public IActionResult GetCurrentUser() => Ok(CreateUserInfo(User));

    private UserInfo CreateUserInfo(ClaimsPrincipal claimsPrincipal)
    {
        if (!claimsPrincipal?.Identity?.IsAuthenticated ?? true)
        {
            return UserInfo.Anonymous;
        }

        var userInfo = new UserInfo
        {
            IsAuthenticated = true
        };

        if (claimsPrincipal?.Identity is ClaimsIdentity claimsIdentity)
        {
            userInfo.NameClaimType = claimsIdentity.NameClaimType;
            userInfo.RoleClaimType = claimsIdentity.RoleClaimType;
        }
        else
        {
            userInfo.NameClaimType = ClaimTypes.Name;
            userInfo.RoleClaimType = ClaimTypes.Role;
        }

        if (claimsPrincipal?.Claims?.Any() ?? false)
        {
            // Add name claim and display name claim
            var claims = new List<ClaimValue>();

            // Add the default name claim
            var nameClaims = claimsPrincipal.FindAll(userInfo.NameClaimType)
                                           .Select(u => new ClaimValue(userInfo.NameClaimType, u.Value));
            claims.AddRange(nameClaims);

            // Add display name claim from Azure (typically "name" claim)
            var displayNameClaim = claimsPrincipal.FindFirst("name");
            if (displayNameClaim != null)
            {
                claims.Add(new ClaimValue("name", displayNameClaim.Value));
            }

            // Add email claim for fallback
            var emailClaim = claimsPrincipal.FindFirst("email")
                          ?? claimsPrincipal.FindFirst("emails")
                          ?? claimsPrincipal.FindFirst(ClaimTypes.Email);
            if (emailClaim != null)
            {
                claims.Add(new ClaimValue("email", emailClaim.Value));
            }

            // Uncomment this code if you want to send all claims to the client.
            //var claims = claimsPrincipal.Claims.Select(u => new ClaimValue(u.Type, u.Value))
            //                                      .ToList();

            userInfo.Claims = claims;
        }

        return userInfo;
    }
}

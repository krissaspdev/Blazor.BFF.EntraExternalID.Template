using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using BlazorBffEntraExternalID.Server.Services;

namespace BlazorBffEntraExternalID.Server.Controllers;

[ValidateAntiForgeryToken]
[Authorize(AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme)]
[ApiController]
[Route("api/[controller]")]
public class DirectApiController : ControllerBase
{
    private readonly ICurrentUserService _currentUserService;

    public DirectApiController(ICurrentUserService currentUserService)
    {
        _currentUserService = currentUserService;
    }

    [HttpGet]
    public IEnumerable<string> Get()
    {
        var userId = _currentUserService.GetUserId();
        var userEmail = _currentUserService.GetUserEmail();

        return new List<string> { "some data", "more data", "loads of data", userId, userEmail };
    }

    /// <summary>
    /// Endpoint accessible ONLY for users with Admin role
    /// </summary>
    [HttpGet("admin-only")]
    [Authorize(Roles = "Admin")]
    public IActionResult GetAdminData()
    {
        var userId = _currentUserService.GetUserId();
        var userName = _currentUserService.GetUserName();

        return Ok(new
        {
            message = "✅ Success! You have access as Administrator",
            userId = userId,
            user = userName,
            endpoint = "admin-only",
            requiredRole = "Admin",
            timestamp = DateTime.UtcNow
        });
    }

    /// <summary>
    /// Endpoint accessible ONLY for users with User role
    /// </summary>
    [HttpGet("user-only")]
    [Authorize(Roles = "User")]
    public IActionResult GetUserData()
    {
        var userId = _currentUserService.GetUserId();
        var userName = _currentUserService.GetUserName();

        return Ok(new
        {
            message = "✅ Success! You have access as User",
            userId = userId,
            user = userName,
            endpoint = "user-only",
            requiredRole = "User",
            timestamp = DateTime.UtcNow
        });
    }

    /// <summary>
    /// Endpoint accessible for users with User OR Admin role
    /// </summary>
    [HttpGet("user-or-admin")]
    [Authorize(Roles = "User,Admin")]
    public IActionResult GetUserOrAdminData()
    {
        var userId = _currentUserService.GetUserId();
        var userName = _currentUserService.GetUserName();
        var userRoles = _currentUserService.GetUserRoles();

        return Ok(new
        {
            message = "✅ Success! You have access as User or Admin",
            userId = userId,
            user = userName,
            roles = userRoles,
            endpoint = "user-or-admin",
            requiredRole = "User or Admin",
            timestamp = DateTime.UtcNow
        });
    }

    /// <summary>
    /// Endpoint showing all information about the authenticated user
    /// Accessible for any authenticated user
    /// </summary>
    [HttpGet("my-info")]
    public IActionResult GetMyInfo()
    {
        var userId = _currentUserService.GetUserId();
        var userName = _currentUserService.GetUserName();
        var userEmail = _currentUserService.GetUserEmail();
        var roles = _currentUserService.GetUserRoles();
        var isAuthenticated = _currentUserService.IsAuthenticated();

        // Keep original claims for debugging purposes
        var claims = User.Claims.Select(c => new
        {
            type = c.Type,
            value = c.Value
        }).ToList();

        return Ok(new
        {
            message = "Information about authenticated user (using ICurrentUserService)",
            userId = userId,
            user = userName,
            email = userEmail,
            isAuthenticated = isAuthenticated,
            roles = roles,
            allClaims = claims,
            timestamp = DateTime.UtcNow
        });
    }

    /// <summary>
    /// Public endpoint without required authorization (for testing)
    /// </summary>
    [HttpGet("public")]
    [AllowAnonymous]
    public IActionResult GetPublicData()
    {
        return Ok(new
        {
            message = "This is a public endpoint - accessible without authentication",
            endpoint = "public",
            requiredRole = "None (AllowAnonymous)",
            timestamp = DateTime.UtcNow
        });
    }

    /// <summary>
    /// Test if user has a specific role
    /// </summary>
    [HttpGet("check-role/{roleName}")]
    public IActionResult CheckRole(string roleName)
    {
        var userId = _currentUserService.GetUserId();
        var userName = _currentUserService.GetUserName();
        var hasRole = _currentUserService.IsInRole(roleName);
        var userRoles = _currentUserService.GetUserRoles();

        return Ok(new
        {
            userId = userId,
            user = userName,
            checkedRole = roleName,
            hasRole = hasRole,
            userRoles = userRoles,
            message = hasRole
                ? $"✅ User HAS role: {roleName}"
                : $"❌ User DOES NOT HAVE role: {roleName}",
            timestamp = DateTime.UtcNow
        });
    }
}

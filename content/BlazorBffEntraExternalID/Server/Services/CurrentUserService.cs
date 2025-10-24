using System.Security.Claims;

namespace BlazorBffEntraExternalID.Server.Services;

/// <summary>
/// Implementation of ICurrentUserService that retrieves user information from HttpContext
/// </summary>
public class CurrentUserService : ICurrentUserService
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public CurrentUserService(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    private ClaimsPrincipal? User => _httpContextAccessor.HttpContext?.User;

    public string? GetUserId()
    {
        if (User == null || !User.Identity?.IsAuthenticated == true)
            return null;

        return User.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier")?.Value
            ?? User.FindFirst("uid")?.Value
            ?? User.FindFirst("preferred_username")?.Value;
    }

    public string? GetUserEmail()
    {
        if (User == null || !User.Identity?.IsAuthenticated == true)
            return null;

        // Try multiple email claim types
        return User.FindFirst(ClaimTypes.Email)?.Value
            ?? User.FindFirst("email")?.Value
            ?? User.FindFirst("emails")?.Value;
    }

    public string GetUserName()
    {
        if (User == null || !User.Identity?.IsAuthenticated == true)
            return "Unknown";

        // Try to get the most appropriate display name
        return User.Identity?.Name
            ?? User.FindFirst(ClaimTypes.Name)?.Value
            ?? User.FindFirst("name")?.Value
            ?? User.FindFirst(ClaimTypes.Email)?.Value
            ?? User.FindFirst("email")?.Value
            ?? "Unknown";
    }

    public bool IsInRole(string role)
    {
        if (User == null || !User.Identity?.IsAuthenticated == true)
            return false;

        return User.IsInRole(role);
    }

    public IEnumerable<string> GetUserRoles()
    {
        if (User == null || !User.Identity?.IsAuthenticated == true)
            return Enumerable.Empty<string>();

        return User.FindAll(ClaimTypes.Role)
            .Select(c => c.Value)
            .ToList();
    }

    public bool IsAuthenticated()
    {
        return User?.Identity?.IsAuthenticated ?? false;
    }
}


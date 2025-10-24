namespace BlazorBffEntraExternalID.Server.Services;

/// <summary>
/// Service for accessing current authenticated user information
/// </summary>
public interface ICurrentUserService
{
    /// <summary>
    /// Gets the unique user identifier (oid, sub, or NameIdentifier claim)
    /// </summary>
    /// <returns>User ID or null if not authenticated</returns>
    string? GetUserId();

    /// <summary>
    /// Gets the user's email address
    /// </summary>
    /// <returns>User email or null if not available</returns>
    string? GetUserEmail();

    /// <summary>
    /// Gets the user's display name
    /// </summary>
    /// <returns>User name or "Unknown" if not available</returns>
    string GetUserName();

    /// <summary>
    /// Checks if the current user has a specific role
    /// </summary>
    /// <param name="role">Role name to check</param>
    /// <returns>True if user has the role, false otherwise</returns>
    bool IsInRole(string role);

    /// <summary>
    /// Gets all roles assigned to the current user
    /// </summary>
    /// <returns>List of role names</returns>
    IEnumerable<string> GetUserRoles();

    /// <summary>
    /// Checks if the current user is authenticated
    /// </summary>
    /// <returns>True if authenticated, false otherwise</returns>
    bool IsAuthenticated();
}


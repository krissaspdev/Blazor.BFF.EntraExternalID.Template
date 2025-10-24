# Continuous Access Evaluation (CAE) - Usage Guide

## 📋 Overview

**Continuous Access Evaluation (CAE)** is an Azure Active Directory feature that enables near real-time enforcement of security policies. It allows:

- **Instant access revocation** when user accounts are disabled or deleted
- **Authentication Context** - requiring additional authentication for sensitive operations
- **Real-time policy enforcement** - immediate response to security events
- **Location-based access control** - enforcing policies based on user location changes

CAE is particularly useful for applications that handle sensitive data and need enhanced security beyond traditional token lifetime management.

## ✅ What's Already Included in This Project

This BFF template already includes the necessary infrastructure for CAE:

### Server-Side Components

1. **`Server/Cae/CaeClaimsChallengeService.cs`**

   - Service for checking authentication context claims
   - Generates claims challenge when required context is missing
   - Already registered in `Program.cs` as scoped service

2. **`Server/Cae/AuthContextId.cs`**

   - Constants for authentication context IDs (`C1`, `C2`, `C3`)
   - Use these to reference your Azure AD authentication contexts

3. **`Server/Cae/WebApiMsalUiRequiredException.cs`**

   - Exception class for CAE challenges from downstream APIs
   - Passes HTTP responses with WWW-Authenticate headers

4. **`Server/Controllers/AccountController.cs`**
   - Already handles `claimsChallenge` parameter in Login action
   - Passes claims to authentication properties

### Client-Side Components

5. **`Client/Services/AuthorizedHandler.cs`**

   - Automatically detects CAE challenges (responses containing "acr")
   - Calls `CaeStepUp()` to redirect to login with claims challenge

6. **`Client/Services/HostAuthenticationStateProvider.cs`**
   - `CaeStepUp()` method for handling claims challenges
   - Redirects to login with claims challenge parameter

## 🔧 Two CAE Scenarios

### Scenario 1: Standalone App (id_token)

Use this when checking authentication context **within your BFF application** without calling downstream APIs.

#### Azure App Registration Configuration

Add to your app registration manifest:

```json
"optionalClaims": {
  "idToken": [
    {
      "name": "xms_cc",
      "source": null,
      "essential": false,
      "additionalProperties": []
    }
  ],
  "accessToken": [],
  "saml2Token": []
}
```

#### Configuration

Add to `appsettings.json`:

```json
{
  "EntraExternalID": {
    "ClientCapabilities": ["cp1"]
  }
}
```

#### Controller Implementation

```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using BlazorBffEntraExternalID.Server;

namespace BlazorBffEntraExternalID.Server.Controllers;

[Authorize]
[ApiController]
[Route("api/[controller]")]
public class SensitiveDataController : ControllerBase
{
    private readonly CaeClaimsChallengeService _caeClaimsChallengeService;
    private readonly ICurrentUserService _currentUserService;

    public SensitiveDataController(
        CaeClaimsChallengeService caeClaimsChallengeService,
        ICurrentUserService currentUserService)
    {
        _caeClaimsChallengeService = caeClaimsChallengeService;
        _currentUserService = currentUserService;
    }

    /// <summary>
    /// Endpoint requiring authentication context C1
    /// If the user doesn't have the required context, returns 401 with claims challenge
    /// </summary>
    [HttpGet("high-security")]
    public IActionResult GetHighSecurityData()
    {
        // Check if user has required authentication context in id_token
        var claimsChallenge = _caeClaimsChallengeService
            .CheckForRequiredAuthContextIdToken(AuthContextId.C1, HttpContext);

        // If CAE claim missing in id token, return claims challenge
        if (claimsChallenge != null)
        {
            return Unauthorized(claimsChallenge);
        }

        // User has required context - proceed with operation
        var userId = _currentUserService.GetUserId();
        return Ok(new
        {
            message = "Access granted to high security data",
            userId = userId,
            requiredAuthContext = AuthContextId.C1,
            data = "Sensitive information"
        });
    }
}
```

### Scenario 2: Downstream API (access_token)

Use this when your BFF calls a **downstream API** that enforces CAE and may return CAE challenges.

#### Azure App Registration Configuration

Add to your app registration manifest:

```json
"optionalClaims": {
  "idToken": [],
  "accessToken": [
    {
      "name": "xms_cc",
      "source": null,
      "essential": false,
      "additionalProperties": []
    }
  ],
  "saml2Token": []
}
```

#### Configuration

Add to `appsettings.json`:

```json
{
  "EntraExternalID": {
    "ClientCapabilities": ["cp1"]
  },
  "DownstreamApi": {
    "BaseUrl": "https://your-api.azurewebsites.net",
    "Scopes": "api://your-api-id/access"
  }
}
```

#### API Service Implementation

```csharp
using Microsoft.Identity.Web;
using System.Net.Http.Headers;
using BlazorBffEntraExternalID.Server;

public class DownstreamApiService
{
    private readonly IHttpClientFactory _clientFactory;
    private readonly ITokenAcquisition _tokenAcquisition;

    public DownstreamApiService(
        IHttpClientFactory clientFactory,
        ITokenAcquisition tokenAcquisition)
    {
        _clientFactory = clientFactory;
        _tokenAcquisition = tokenAcquisition;
    }

    public async Task<T> CallApiAsync<T>(string url, string[] scopes)
    {
        var client = _clientFactory.CreateClient();

        // Acquire access token for downstream API
        var accessToken = await _tokenAcquisition
            .GetAccessTokenForUserAsync(scopes);

        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", accessToken);

        var response = await client.GetAsync(url);

        if (response.IsSuccessStatusCode)
        {
            var stream = await response.Content.ReadAsStreamAsync();
            var payload = await JsonSerializer.DeserializeAsync<T>(stream);
            return payload;
        }

        // Check if it's a CAE challenge (WWW-Authenticate header)
        // Throw exception to be caught by controller
        throw new WebApiMsalUiRequiredException(
            $"Error: {response.StatusCode}", response);
    }
}
```

#### Controller with Downstream API

```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Web;
using BlazorBffEntraExternalID.Server;

[Authorize]
[ApiController]
[Route("api/[controller]")]
public class ProxyController : ControllerBase
{
    private readonly DownstreamApiService _apiService;

    public ProxyController(DownstreamApiService apiService)
    {
        _apiService = apiService;
    }

    [HttpGet("data")]
    public async Task<IActionResult> GetDataFromDownstreamApi()
    {
        try
        {
            // Call downstream API that may return CAE challenge
            var data = await _apiService.CallApiAsync<MyData>(
                "https://downstream-api.com/api/data",
                new[] { "api://downstream-api/access" });

            return Ok(data);
        }
        catch (WebApiMsalUiRequiredException hex)
        {
            // Extract claims challenge from WWW-Authenticate header
            var claimChallenge = WwwAuthenticateParameters
                .GetClaimChallengeFromResponseHeaders(hex.Headers);

            // Return 401 with claims challenge
            // Client's AuthorizedHandler will catch this and trigger step-up auth
            return Unauthorized(claimChallenge);
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { error = ex.Message });
        }
    }
}
```

## 🔐 Azure Portal Configuration

### Step 1: Create Authentication Contexts

1. Navigate to **Azure Portal** → **Azure Active Directory**
2. Go to **Security** → **Conditional Access** → **Authentication context**
3. Click **New authentication context**
4. Create contexts matching your `AuthContextId` constants:
   - **ID**: `c1`, **Display name**: "High Security Operations"
   - **ID**: `c2`, **Display name**: "Critical Operations"
   - **ID**: `c3`, **Display name**: "Maximum Security Operations"

### Step 2: Create Conditional Access Policy

1. Go to **Security** → **Conditional Access** → **Policies**
2. Click **New policy**:
   - **Name**: "Require MFA for High Security Operations"
   - **Users**: Select target users/groups
   - **Cloud apps**: Select your application
   - **Authentication context**: Select "High Security Operations" (c1)
   - **Grant controls**: Check "Require multi-factor authentication"
   - **Enable policy**: Turn on

### Step 3: App Registration - Optional Claims

1. Go to **App registrations** → Your app → **Token configuration**
2. Click **Add optional claim**
3. Select token type based on scenario:
   - **Standalone app**: Select "ID" and add `xms_cc`
   - **Downstream API**: Select "Access" and add `xms_cc`

### Step 4: Update appsettings.json

Ensure `ClientCapabilities` is configured:

```json
{
  "EntraExternalID": {
    "Instance": "https://login.microsoftonline.com/",
    "TenantId": "your-tenant-id",
    "ClientId": "your-client-id",
    "ClientSecret": "your-client-secret",
    "ClientCapabilities": ["cp1"],
    "CallbackPath": "/signin-oidc"
  }
}
```

## 🔄 How CAE Works - Flow

### Standalone Flow (id_token)

1. User calls protected endpoint (e.g., `/api/SensitiveData/high-security`)
2. `CaeClaimsChallengeService` checks for `acrs` claim with required value
3. If missing → returns `401 Unauthorized` with claims challenge JSON
4. Client's `AuthorizedHandler` detects `"acr"` in response
5. Calls `CaeStepUp(claimsChallenge)` to redirect to login
6. `AccountController.Login` receives `claimsChallenge` parameter
7. Azure AD enforces Conditional Access policy (e.g., MFA)
8. User completes authentication and returns with new id_token containing `acrs` claim
9. Next API call succeeds with proper authentication context

### Downstream API Flow (access_token)

1. User calls BFF endpoint that proxies to downstream API
2. BFF acquires access token for downstream API
3. Downstream API checks CAE claims in access token
4. If insufficient → returns `401` with `WWW-Authenticate` header
5. BFF catches `WebApiMsalUiRequiredException`
6. Extracts claims challenge from headers
7. Returns `401 Unauthorized` to client with claims challenge
8. Client flow continues as in standalone scenario
9. User completes step-up authentication
10. New access token with proper claims is acquired
11. Downstream API call succeeds

## 🧪 Testing CAE

### Check Current Authentication Context

Add this endpoint to verify current user's authentication context:

```csharp
[HttpGet("auth-context-info")]
public IActionResult GetAuthContextInfo()
{
    var acrsClaim = User.FindFirst("acrs")?.Value;
    var xmsCcClaim = User.FindFirst("xms_cc")?.Value;

    return Ok(new
    {
        hasAuthContext = acrsClaim != null,
        authContextValue = acrsClaim,
        hasClientCapability = xmsCcClaim != null,
        clientCapabilityValue = xmsCcClaim,
        allClaims = User.Claims.Select(c => new { c.Type, c.Value }).ToList()
    });
}
```

### Testing Checklist

- [ ] Azure AD Premium P1 or P2 license
- [ ] Authentication context created in Azure AD
- [ ] Conditional Access policy configured and enabled
- [ ] Optional claims (`xms_cc`) added to app registration
- [ ] `ClientCapabilities: ["cp1"]` in appsettings.json
- [ ] Test with user who should trigger policy
- [ ] Verify MFA or other requirements are enforced

## 📊 Authentication Context Levels

Define your own business logic for each level in `AuthContextId.cs`:

| Context ID | Suggested Use Case   | Example Policy                                  |
| ---------- | -------------------- | ----------------------------------------------- |
| `c1`       | Sensitive operations | Require MFA                                     |
| `c2`       | Critical operations  | Require MFA + Compliant device                  |
| `c3`       | Maximum security     | Require MFA + Managed device + Trusted location |

## ⚠️ Important Notes

1. **CAE requires Azure AD Premium P1** or higher license
2. **Client capabilities** must be declared: `ClientCapabilities: ["cp1"]`
3. **Optional claims** (`xms_cc`) must be configured in app registration manifest
4. **Conditional Access policies** must reference authentication contexts
5. **Testing locally**: CAE works even in development, but requires proper Azure AD configuration
6. **Token lifetime**: CAE enables real-time revocation beyond standard token expiration
7. **Network latency**: CAE checks may add minimal latency to API calls

## 🔗 References

- [Microsoft Documentation: CAE](https://docs.microsoft.com/en-us/azure/active-directory/develop/app-resilience-continuous-access-evaluation)
- [Authentication Context](https://docs.microsoft.com/en-us/azure/active-directory/develop/developer-guide-conditional-access-authentication-context)
- [Claims Challenge](https://docs.microsoft.com/en-us/azure/active-directory/develop/claims-challenge)

## 🚀 Quick Start

1. Enable CAE in `appsettings.json`: Add `"ClientCapabilities": ["cp1"]`
2. Configure optional claims in Azure app registration
3. Create authentication context in Azure AD
4. Create Conditional Access policy
5. Use `CaeClaimsChallengeService` in your controllers (Scenario 1) or catch `WebApiMsalUiRequiredException` (Scenario 2)
6. Client-side handling is already implemented in `AuthorizedHandler`

---

**Note**: All infrastructure for CAE is already included in this template. You only need to configure Azure AD and implement your business logic in controllers.

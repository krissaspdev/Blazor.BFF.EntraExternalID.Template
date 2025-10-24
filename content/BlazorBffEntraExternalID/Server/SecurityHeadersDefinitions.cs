using Microsoft.AspNetCore.Builder;

namespace BlazorBffEntraExternalID.Server;

public static class SecurityHeadersDefinitions
{
    private const string LoginLiveUrl = "https://login.live.com";
    private const string LoginCdnMsAuthUrl = "https://logincdn.msauth.net";

    public static HeaderPolicyCollection GetHeaderPolicyCollection(bool isDev, string? idpHost)
    {
        if (idpHost == null)
        {
            throw new ArgumentNullException(nameof(idpHost));
        }

        var policy = new HeaderPolicyCollection()
            .AddFrameOptionsDeny()
            .AddContentTypeOptionsNoSniff()
            .AddReferrerPolicyStrictOriginWhenCrossOrigin()
            .AddCrossOriginOpenerPolicy(builder => builder.SameOrigin())
            .AddCrossOriginResourcePolicy(builder => builder.SameOrigin())
            .AddCrossOriginEmbedderPolicy(builder => builder.RequireCorp()) // remove for dev if using hot reload
            .AddContentSecurityPolicy(builder =>
            {
                builder.AddObjectSrc().None();
                builder.AddBlockAllMixedContent();
                builder.AddImgSrc().Self().From("data:");
                builder.AddFormAction().Self().From(idpHost).From(LoginLiveUrl);
                builder.AddFontSrc().Self().From("https://fonts.gstatic.com");
                builder.AddStyleSrc().Self().From("https://fonts.googleapis.com").UnsafeInline();
                builder.AddBaseUri().Self();
                builder.AddFrameAncestors().None();

                // due to Blazor
                builder.AddScriptSrc()
                .From(idpHost)
                .From(LoginCdnMsAuthUrl)
                .From(LoginLiveUrl)
                    .WithHash256("sha256-wTSw2ZoYOVpX8Sl5cEiYcCF8ddvCbjJhiX+oYQqD1s4=")
                    .WithNonce()
                    .UnsafeEval() // due to Blazor WASM
                    .StrictDynamic()
                    .UnsafeInline(); // only a fallback for older browsers when the nonce is used 

                // disable script and style CSP protection if using Blazor hot reload
                // if using hot reload, DO NOT deploy with an insecure CSP
            })
            .RemoveServerHeader()
            .AddPermissionsPolicy(builder =>
            {
                builder.AddAccelerometer().None();
                builder.AddAutoplay().None();
                builder.AddCamera().None();
                builder.AddEncryptedMedia().None();
                builder.AddFullscreen().All();
                builder.AddGeolocation().None();
                builder.AddGyroscope().None();
                builder.AddMagnetometer().None();
                builder.AddMicrophone().None();
                builder.AddMidi().None();
                builder.AddPayment().None();
                builder.AddPictureInPicture().None();
                builder.AddSyncXHR().None();
                builder.AddUsb().None();
            });

        if (!isDev)
        {
            // maxage = one year in seconds
            policy.AddStrictTransportSecurityMaxAgeIncludeSubDomains(maxAgeInSeconds: 60 * 60 * 24 * 365);
        }

        policy.ApplyDocumentHeadersToAllResponses();

        return policy;
    }
}

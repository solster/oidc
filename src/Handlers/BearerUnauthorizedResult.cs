namespace Solster.Authentication.OpenIdConnect.Handlers;

/// <summary>
/// Returns a 401 Unauthorized response with RFC 6750 compliant WWW-Authenticate header.
/// </summary>
internal class BearerUnauthorizedResult : IResult
{
    private readonly String _errorDescription;

    public BearerUnauthorizedResult(String errorDescription)
    {
        _errorDescription = errorDescription;
    }

    public async Task ExecuteAsync(HttpContext httpContext)
    {
        httpContext.Response.StatusCode = StatusCodes.Status401Unauthorized;
        httpContext.Response.ContentType = "application/json; charset=utf-8";
        
        // RFC 6750 §3.1: REQUIRED WWW-Authenticate header with Bearer scheme
        httpContext.Response.Headers.WWWAuthenticate = 
            $"Bearer error=\"invalid_token\", error_description=\"{EscapeForHeader(_errorDescription)}\"";
        
        var errorResponse = new 
        { 
            error = "invalid_token", 
            error_description = _errorDescription 
        };
        
        await httpContext.Response.WriteAsJsonAsync(errorResponse);
    }

    /// <summary>
    /// Escapes quotes in error description for HTTP header value.
    /// </summary>
    private static String EscapeForHeader(String value)
    {
        return value.Replace("\"", "\\\"");
    }
}

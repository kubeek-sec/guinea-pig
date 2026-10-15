using Toolshed.Auth;
using Toolshed.Store;

namespace Toolshed.Api;

/// <summary>Resolves the member behind a request and enforces the staff role.</summary>
public static class Sessions
{
    public static (Member? Member, IResult? Refusal) Required(TokenService tokens, HttpRequest request)
    {
        var member = tokens.FromHeader(request.Headers.Authorization);
        return member is null
            ? (null, Results.Json(new { error = "authentication required" }, statusCode: 401))
            : (member, null);
    }

    public static (Member? Member, IResult? Refusal) Staff(TokenService tokens, HttpRequest request)
    {
        var (member, refusal) = Required(tokens, request);
        if (refusal is not null)
        {
            return (null, refusal);
        }
        return member!.Role == "staff"
            ? (member, null)
            : (null, Results.Json(new { error = "staff only" }, statusCode: 403));
    }
}

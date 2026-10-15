using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

using Microsoft.IdentityModel.Tokens;

using Toolshed.Store;

namespace Toolshed.Auth;

/// <summary>Issues and reads the bearer tokens of a member session.</summary>
public sealed class TokenService(Repositories repositories)
{
    public const string Algorithm = SecurityAlgorithms.HmacSha256;

    private static SymmetricSecurityKey SigningKey()
    {
        var key = Environment.GetEnvironmentVariable("TOOLSHED_TOKEN_KEY");
        if (string.IsNullOrWhiteSpace(key))
        {
            throw new InvalidOperationException("TOOLSHED_TOKEN_KEY is not set");
        }
        return new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
    }

    private static int Ttl() =>
        int.TryParse(Environment.GetEnvironmentVariable("TOOLSHED_TOKEN_TTL"), out var v) && v > 0
            ? v
            : 3600;

    public string Issue(Member member)
    {
        var credentials = new SigningCredentials(SigningKey(), Algorithm);
        var token = new JwtSecurityToken(
            claims:
            [
                new Claim(JwtRegisteredClaimNames.Sub, member.Id.ToString()),
                new Claim("email", member.Email),
                new Claim("role", member.Role),
            ],
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddSeconds(Ttl()),
            signingCredentials: credentials);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public Member? Authenticate(string email, string password)
    {
        var member = repositories.MemberByEmail(email);
        if (member is null || !BCrypt.Net.BCrypt.Verify(password, member.Password))
        {
            return null;
        }
        return member;
    }

    public Member? FromHeader(string? authorization)
    {
        if (authorization is null || !authorization.StartsWith("Bearer ", StringComparison.Ordinal))
        {
            return null;
        }
        var parameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = SigningKey(),
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ValidAlgorithms = [Algorithm],
            ClockSkew = TimeSpan.Zero,
        };
        try
        {
            var principal = new JwtSecurityTokenHandler()
                .ValidateToken(authorization[7..], parameters, out _);
            var subject = principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value
                          ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            return long.TryParse(subject, out var id) ? repositories.Member(id) : null;
        }
        catch (Exception e) when (e is SecurityTokenException or ArgumentException)
        {
            return null;
        }
    }
}

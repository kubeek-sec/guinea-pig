using System.Net;
using System.Security.Cryptography;

using Toolshed.Auth;
using Toolshed.Store;

namespace Toolshed.Api;

/// <summary>The HTTP surface of the workshop.</summary>
public static class Endpoints
{
    private static readonly HashSet<string> Sortable = ["name", "category", "daily_rate"];
    private static readonly HashSet<string> Accepted = [".jpg", ".jpeg", ".png", ".webp"];
    private const int DefaultDays = 7;
    private const long MaxPhotoBytes = 8L * 1024 * 1024;

    public static void MapCatalog(this WebApplication app)
    {
        app.MapGet("/healthz", () => Results.Json(new { status = "ok", version = Program.Version }));

        app.MapGet("/openapi.yml", () =>
            Results.File(Path.Combine(AppContext.BaseDirectory, "openapi.yml"), "application/yaml"));

        app.MapGet("/", (Repositories repo) =>
        {
            var rows = string.Join("\n", repo.TopTools(20).Select(t =>
                $"<tr><td>{WebUtility.HtmlEncode(t.Name)}</td>" +
                $"<td>{WebUtility.HtmlEncode(t.Category)}</td>" +
                $"<td>{t.DailyRate:F2} &euro;</td>" +
                $"<td>{(t.Available ? "on the rack" : "<span class=\"out\">out</span>")}</td></tr>"));
            return Results.Content($$"""
                <!doctype html>
                <html lang="en">
                <head><meta charset="utf-8"><title>Toolshed</title>
                <style>body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:48rem}
                table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid #ddd;padding:.5rem;text-align:left}
                .out{color:#999}</style></head>
                <body><h1>Toolshed</h1><p>Tools the workshop lends to its members.</p>
                <table><tr><th>Tool</th><th>Category</th><th>Per day</th><th>Status</th></tr>
                {{rows}}
                </table><p><a href="/openapi.yml">API description</a></p></body></html>
                """, "text/html");
        });

        app.MapGet("/api/tools", (Repositories repo, string? sort) =>
        {
            var column = sort ?? "name";
            return Sortable.Contains(column)
                ? Results.Json(new { tools = repo.ToolsOrderedBy(column) })
                : Results.Json(new { error = $"cannot sort on '{column}'" }, statusCode: 400);
        });

        app.MapGet("/api/tools/search", (Repositories repo, string? q) =>
            Results.Json(new { query = q ?? "", tools = repo.SearchTools(q ?? "") }));

        app.MapGet("/api/tools/{id:long}", (Repositories repo, long id) =>
        {
            var tool = repo.Tool(id);
            return tool is null
                ? Results.Json(new { error = "no such tool" }, statusCode: 404)
                : Results.Json(tool);
        });
    }

    public record Credentials(string? Email, string? Password);

    public static void MapMembers(this WebApplication app)
    {
        app.MapPost("/api/session", (TokenService tokens, Credentials body) =>
        {
            var member = tokens.Authenticate(body.Email ?? "", body.Password ?? "");
            return member is null
                ? Results.Json(new { error = "bad credentials" }, statusCode: 401)
                : Results.Json(new { token = tokens.Issue(member), role = member.Role });
        });

        app.MapGet("/api/members/me", (TokenService tokens, HttpRequest request) =>
        {
            var (member, refusal) = Sessions.Required(tokens, request);
            return refusal ?? Results.Json(new
            {
                id = member!.Id, email = member.Email,
                full_name = member.FullName, role = member.Role,
            });
        });

        app.MapGet("/api/members/{id:long}", (TokenService tokens, Repositories repo,
                                              HttpRequest request, long id) =>
        {
            var (_, refusal) = Sessions.Staff(tokens, request);
            if (refusal is not null)
            {
                return refusal;
            }
            var member = repo.Member(id);
            return member is null
                ? Results.Json(new { error = "no such member" }, statusCode: 404)
                : Results.Json(new
                {
                    id = member.Id, email = member.Email,
                    full_name = member.FullName, role = member.Role,
                });
        });
    }

    public record TakeOut(long? ToolId, int? Days, string? Notes);

    public static void MapRentals(this WebApplication app)
    {
        app.MapGet("/api/rentals", (TokenService tokens, Repositories repo, HttpRequest request) =>
        {
            var (member, refusal) = Sessions.Required(tokens, request);
            return refusal ?? Results.Json(new { rentals = repo.RentalsOf(member!.Id) });
        });

        app.MapPost("/api/rentals", (TokenService tokens, Repositories repo,
                                     HttpRequest request, TakeOut body) =>
        {
            var (member, refusal) = Sessions.Required(tokens, request);
            if (refusal is not null)
            {
                return refusal;
            }
            var tool = repo.Tool(body.ToolId ?? -1);
            if (tool is null)
            {
                return Results.Json(new { error = "no such tool" }, statusCode: 404);
            }
            if (!tool.Available)
            {
                return Results.Json(new { error = "already out" }, statusCode: 409);
            }
            var days = body.Days is > 0 ? body.Days.Value : DefaultDays;
            var today = DateOnly.FromDateTime(DateTime.UtcNow);
            var due = today.AddDays(days);
            var id = repo.CreateRental(member!.Id, tool.Id, today.ToString("yyyy-MM-dd"),
                due.ToString("yyyy-MM-dd"), body.Notes ?? "");
            repo.SetToolAvailable(tool.Id, false);
            return Results.Json(new { id, due_on = due.ToString("yyyy-MM-dd") }, statusCode: 201);
        });

        app.MapPost("/api/rentals/{id:long}/return", (TokenService tokens, Repositories repo,
                                                      HttpRequest request, long id) =>
        {
            var (member, refusal) = Sessions.Required(tokens, request);
            if (refusal is not null)
            {
                return refusal;
            }
            var rental = repo.RentalOf(id, member!.Id);
            if (rental is null)
            {
                return Results.Json(new { error = "no such rental" }, statusCode: 404);
            }
            repo.CloseRental(rental.Id);
            repo.SetToolAvailable(rental.ToolId, true);
            return Results.Json(new { status = "returned" });
        });
    }

    public static void MapPhotos(this WebApplication app, string uploadDir)
    {
        app.MapPost("/api/photos", async (TokenService tokens, HttpRequest request) =>
        {
            var (member, refusal) = Sessions.Required(tokens, request);
            if (refusal is not null)
            {
                return refusal;
            }
            if (!request.HasFormContentType)
            {
                return Results.Json(new { error = "no photo" }, statusCode: 400);
            }
            var form = await request.ReadFormAsync();
            var photo = form.Files["photo"];
            if (photo is null || photo.Length == 0)
            {
                return Results.Json(new { error = "no photo" }, statusCode: 400);
            }
            if (photo.Length > MaxPhotoBytes)
            {
                return Results.Json(new { error = "photo too large" }, statusCode: 400);
            }
            var ext = Path.GetExtension(photo.FileName).ToLowerInvariant();
            if (!Accepted.Contains(ext))
            {
                return Results.Json(new { error = $"{(ext.Length == 0 ? "file" : ext)} not accepted" },
                    statusCode: 400);
            }
            var name = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant() + ext;
            await using var destination = File.Create(Path.Combine(uploadDir, name));
            await photo.CopyToAsync(destination);
            return Results.Json(new { name, owner = member!.Email }, statusCode: 201);
        });

        app.MapGet("/api/photos/{name}", (HttpResponse response, string name) =>
        {
            var file = Path.Combine(uploadDir, Path.GetFileName(name));
            if (!File.Exists(file))
            {
                return Results.Json(new { error = "no such photo" }, statusCode: 404);
            }
            response.Headers["X-Content-Type-Options"] = "nosniff";
            return Results.File(file);
        });
    }
}

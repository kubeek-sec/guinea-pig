using System.Text.Json;
using System.Text.Json.Serialization;

using Toolshed.Api;
using Toolshed.Auth;
using Toolshed.Store;

namespace Toolshed;

/// <summary>Toolshed — the lending service of a neighbourhood workshop.</summary>
public static class Program
{
    public const string Version = "1.4.2";

    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        var dbFile = Environment.GetEnvironmentVariable("TOOLSHED_DB")
                     ?? Path.Combine("var", "toolshed.db");
        var uploadDir = Environment.GetEnvironmentVariable("TOOLSHED_UPLOADS")
                        ?? Path.Combine("var", "uploads");
        Directory.CreateDirectory(uploadDir);

        var database = new Database(dbFile);
        database.Initialize();

        builder.Services.AddSingleton(database);
        builder.Services.AddSingleton<Repositories>();
        builder.Services.AddSingleton<TokenService>();
        builder.Services.ConfigureHttpJsonOptions(options =>
        {
            options.SerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower;
            options.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
        });

        var port = Environment.GetEnvironmentVariable("PORT") ?? "8000";
        builder.WebHost.UseUrls($"http://0.0.0.0:{port}");

        var app = builder.Build();
        app.MapCatalog();
        app.MapMembers();
        app.MapRentals();
        app.MapPhotos(uploadDir);
        app.Run();
    }
}

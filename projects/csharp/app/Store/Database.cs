using Microsoft.Data.Sqlite;

namespace Toolshed.Store;

/// <summary>SQLite access layer and the initial dataset of the workshop.</summary>
public sealed class Database
{
    private const string Ddl = """
        CREATE TABLE IF NOT EXISTS members (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            email     TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            password  TEXT NOT NULL,
            role      TEXT NOT NULL DEFAULT 'member'
        );
        CREATE TABLE IF NOT EXISTS tools (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            category    TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            daily_rate  REAL NOT NULL DEFAULT 0,
            available   INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS rentals (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id INTEGER NOT NULL REFERENCES members(id),
            tool_id   INTEGER NOT NULL REFERENCES tools(id),
            taken_on  TEXT NOT NULL,
            due_on    TEXT NOT NULL,
            notes     TEXT NOT NULL DEFAULT '',
            returned  INTEGER NOT NULL DEFAULT 0
        );
        """;

    private static readonly (string Name, string Category, string Description, double Rate)[] SeedTools =
    [
        ("Circular saw", "cutting", "190 mm blade, 1400 W", 12.5),
        ("Impact driver", "drilling", "18 V, two batteries", 8.0),
        ("Mitre saw", "cutting", "Sliding, 255 mm", 18.0),
        ("Heat gun", "finishing", "2000 W, variable", 5.5),
        ("Mortar mixer", "masonry", "1600 W, 140 mm paddle", 15.0),
    ];

    private static readonly (string Email, string Name, string Password, string Role)[] SeedMembers =
    [
        ("ada@toolshed.example", "Ada Mallory", "workshop-keeper", "staff"),
        ("jun@toolshed.example", "Jun Watanabe", "sawdust-season", "member"),
        ("pierre@toolshed.example", "Pierre Lefranc", "bench-grinder", "member"),
    ];

    private readonly string _connectionString;

    public Database(string file)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(file));
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }
        _connectionString = new SqliteConnectionStringBuilder { DataSource = file }.ToString();
    }

    public SqliteConnection Connect()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();
        return connection;
    }

    public void Initialize()
    {
        using var connection = Connect();
        using (var ddl = connection.CreateCommand())
        {
            ddl.CommandText = Ddl;
            ddl.ExecuteNonQuery();
        }

        using var count = connection.CreateCommand();
        count.CommandText = "SELECT COUNT(*) FROM tools";
        if (Convert.ToInt64(count.ExecuteScalar()) > 0)
        {
            return;
        }

        foreach (var tool in SeedTools)
        {
            using var insert = connection.CreateCommand();
            insert.CommandText =
                "INSERT INTO tools (name, category, description, daily_rate) VALUES ($n, $c, $d, $r)";
            insert.Parameters.AddWithValue("$n", tool.Name);
            insert.Parameters.AddWithValue("$c", tool.Category);
            insert.Parameters.AddWithValue("$d", tool.Description);
            insert.Parameters.AddWithValue("$r", tool.Rate);
            insert.ExecuteNonQuery();
        }

        foreach (var member in SeedMembers)
        {
            using var insert = connection.CreateCommand();
            insert.CommandText =
                "INSERT INTO members (email, full_name, password, role) VALUES ($e, $n, $p, $r)";
            insert.Parameters.AddWithValue("$e", member.Email);
            insert.Parameters.AddWithValue("$n", member.Name);
            insert.Parameters.AddWithValue("$p", BCrypt.Net.BCrypt.HashPassword(member.Password));
            insert.Parameters.AddWithValue("$r", member.Role);
            insert.ExecuteNonQuery();
        }
    }
}

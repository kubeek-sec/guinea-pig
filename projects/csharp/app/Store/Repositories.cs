using Microsoft.Data.Sqlite;

namespace Toolshed.Store;

/// <summary>Read and write access to the three tables of the workshop.</summary>
public sealed class Repositories(Database database)
{
    private static Tool ReadTool(SqliteDataReader r) => new(
        r.GetInt64(r.GetOrdinal("id")), r.GetString(r.GetOrdinal("name")),
        r.GetString(r.GetOrdinal("category")), r.GetString(r.GetOrdinal("description")),
        r.GetDouble(r.GetOrdinal("daily_rate")), r.GetInt64(r.GetOrdinal("available")) != 0);

    private static Member ReadMember(SqliteDataReader r) => new(
        r.GetInt64(r.GetOrdinal("id")), r.GetString(r.GetOrdinal("email")),
        r.GetString(r.GetOrdinal("full_name")), r.GetString(r.GetOrdinal("password")),
        r.GetString(r.GetOrdinal("role")));

    private static Rental ReadRental(SqliteDataReader r, bool withToolName) => new(
        r.GetInt64(r.GetOrdinal("id")), r.GetInt64(r.GetOrdinal("member_id")),
        r.GetInt64(r.GetOrdinal("tool_id")),
        withToolName ? r.GetString(r.GetOrdinal("tool_name")) : null,
        r.GetString(r.GetOrdinal("taken_on")), r.GetString(r.GetOrdinal("due_on")),
        r.GetString(r.GetOrdinal("notes")), r.GetInt64(r.GetOrdinal("returned")) != 0);

    public List<Tool> ToolsOrderedBy(string column)
    {
        using var connection = database.Connect();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT * FROM tools ORDER BY " + column;
        using var reader = command.ExecuteReader();
        var tools = new List<Tool>();
        while (reader.Read())
        {
            tools.Add(ReadTool(reader));
        }
        return tools;
    }

    public List<Tool> TopTools(int limit)
    {
        using var connection = database.Connect();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT * FROM tools ORDER BY name LIMIT $limit";
        command.Parameters.AddWithValue("$limit", limit);
        using var reader = command.ExecuteReader();
        var tools = new List<Tool>();
        while (reader.Read())
        {
            tools.Add(ReadTool(reader));
        }
        return tools;
    }

    public List<Tool> SearchTools(string term)
    {
        using var connection = database.Connect();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT * FROM tools WHERE name LIKE $t OR description LIKE $t";
        command.Parameters.AddWithValue("$t", $"%{term}%");
        using var reader = command.ExecuteReader();
        var tools = new List<Tool>();
        while (reader.Read())
        {
            tools.Add(ReadTool(reader));
        }
        return tools;
    }

    public Tool? Tool(long id)
    {
        using var connection = database.Connect();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT * FROM tools WHERE id = $id";
        command.Parameters.AddWithValue("$id", id);
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadTool(reader) : null;
    }

    public Member? MemberByEmail(string email)
    {
        using var connection = database.Connect();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT * FROM members WHERE email = $e";
        command.Parameters.AddWithValue("$e", email);
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadMember(reader) : null;
    }

    public Member? Member(long id)
    {
        using var connection = database.Connect();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT * FROM members WHERE id = $id";
        command.Parameters.AddWithValue("$id", id);
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadMember(reader) : null;
    }

    public List<Rental> RentalsOf(long memberId)
    {
        using var connection = database.Connect();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT r.*, t.name AS tool_name FROM rentals r
            JOIN tools t ON t.id = r.tool_id
            WHERE r.member_id = $m ORDER BY r.taken_on DESC
            """;
        command.Parameters.AddWithValue("$m", memberId);
        using var reader = command.ExecuteReader();
        var rentals = new List<Rental>();
        while (reader.Read())
        {
            rentals.Add(ReadRental(reader, withToolName: true));
        }
        return rentals;
    }

    public Rental? RentalOf(long rentalId, long memberId)
    {
        using var connection = database.Connect();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT * FROM rentals WHERE id = $r AND member_id = $m";
        command.Parameters.AddWithValue("$r", rentalId);
        command.Parameters.AddWithValue("$m", memberId);
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadRental(reader, withToolName: false) : null;
    }

    public long CreateRental(long memberId, long toolId, string takenOn, string dueOn, string notes)
    {
        using var connection = database.Connect();
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO rentals (member_id, tool_id, taken_on, due_on, notes)
            VALUES ($m, $t, $taken, $due, $notes);
            SELECT last_insert_rowid();
            """;
        command.Parameters.AddWithValue("$m", memberId);
        command.Parameters.AddWithValue("$t", toolId);
        command.Parameters.AddWithValue("$taken", takenOn);
        command.Parameters.AddWithValue("$due", dueOn);
        command.Parameters.AddWithValue("$notes", notes);
        return Convert.ToInt64(command.ExecuteScalar());
    }

    public void SetToolAvailable(long toolId, bool available)
    {
        using var connection = database.Connect();
        using var command = connection.CreateCommand();
        command.CommandText = "UPDATE tools SET available = $a WHERE id = $id";
        command.Parameters.AddWithValue("$a", available ? 1 : 0);
        command.Parameters.AddWithValue("$id", toolId);
        command.ExecuteNonQuery();
    }

    public void CloseRental(long rentalId)
    {
        using var connection = database.Connect();
        using var command = connection.CreateCommand();
        command.CommandText = "UPDATE rentals SET returned = 1 WHERE id = $id";
        command.Parameters.AddWithValue("$id", rentalId);
        command.ExecuteNonQuery();
    }
}

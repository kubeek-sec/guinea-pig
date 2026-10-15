using System.Text.Json.Serialization;

namespace Toolshed.Store;

public record Tool(long Id, string Name, string Category, string Description,
                   double DailyRate, bool Available);

public record Member(long Id, string Email, string FullName,
                     [property: JsonIgnore] string Password, string Role);

public record Rental(long Id, long MemberId, long ToolId, string? ToolName,
                     string TakenOn, string DueOn, string Notes, bool Returned);

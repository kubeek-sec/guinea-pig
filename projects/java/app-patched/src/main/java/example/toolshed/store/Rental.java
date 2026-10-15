package example.toolshed.store;

public record Rental(long id, long memberId, long toolId, String toolName,
                     String takenOn, String dueOn, String notes, boolean returned) {
}

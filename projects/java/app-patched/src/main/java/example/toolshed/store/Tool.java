package example.toolshed.store;

public record Tool(long id, String name, String category, String description,
                   double dailyRate, boolean available) {
}

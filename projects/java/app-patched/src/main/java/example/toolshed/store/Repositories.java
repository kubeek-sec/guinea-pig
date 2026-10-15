package example.toolshed.store;

import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

/** Read and write access to the three tables of the workshop. */
@Repository
public class Repositories {

    private final JdbcTemplate jdbc;

    public Repositories(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public JdbcTemplate jdbc() {
        return jdbc;
    }

    public static final RowMapper<Tool> TOOL = (rs, n) -> new Tool(
            rs.getLong("id"), rs.getString("name"), rs.getString("category"),
            rs.getString("description"), rs.getDouble("daily_rate"), rs.getBoolean("available"));

    public static final RowMapper<Member> MEMBER = (rs, n) -> new Member(
            rs.getLong("id"), rs.getString("email"), rs.getString("full_name"),
            rs.getString("password"), rs.getString("role"));

    public static final RowMapper<Rental> RENTAL = (rs, n) -> new Rental(
            rs.getLong("id"), rs.getLong("member_id"), rs.getLong("tool_id"),
            hasColumn(rs, "tool_name") ? rs.getString("tool_name") : null,
            rs.getString("taken_on"), rs.getString("due_on"),
            rs.getString("notes"), rs.getBoolean("returned"));

    private static boolean hasColumn(java.sql.ResultSet rs, String label) {
        try {
            rs.findColumn(label);
            return true;
        } catch (java.sql.SQLException e) {
            return false;
        }
    }

    public List<Tool> toolsOrderedBy(String column) {
        return jdbc.query("SELECT * FROM tools ORDER BY " + column, TOOL);
    }

    public List<Tool> topTools(int limit) {
        return jdbc.query("SELECT * FROM tools ORDER BY name LIMIT ?", TOOL, limit);
    }

    public List<Tool> searchTools(String term) {
        String like = "%" + term + "%";
        return jdbc.query("SELECT * FROM tools WHERE name LIKE ? OR description LIKE ?",
                TOOL, like, like);
    }

    public Optional<Tool> tool(long id) {
        return jdbc.query("SELECT * FROM tools WHERE id = ?", TOOL, id).stream().findFirst();
    }

    public Optional<Member> memberByEmail(String email) {
        return jdbc.query("SELECT * FROM members WHERE email = ?", MEMBER, email).stream().findFirst();
    }

    public Optional<Member> member(long id) {
        return jdbc.query("SELECT * FROM members WHERE id = ?", MEMBER, id).stream().findFirst();
    }

    public List<Rental> rentalsOf(long memberId) {
        return jdbc.query("""
                SELECT r.*, t.name AS tool_name FROM rentals r
                JOIN tools t ON t.id = r.tool_id
                WHERE r.member_id = ? ORDER BY r.taken_on DESC""", RENTAL, memberId);
    }

    public Optional<Rental> rentalOf(long rentalId, long memberId) {
        return jdbc.query("SELECT * FROM rentals WHERE id = ? AND member_id = ?",
                RENTAL, rentalId, memberId).stream().findFirst();
    }

    public long createRental(long memberId, long toolId, String takenOn, String dueOn, String notes) {
        jdbc.update("INSERT INTO rentals (member_id, tool_id, taken_on, due_on, notes) VALUES (?, ?, ?, ?, ?)",
                memberId, toolId, takenOn, dueOn, notes);
        Long id = jdbc.queryForObject("SELECT last_insert_rowid()", Long.class);
        return id == null ? 0L : id;
    }

    public void setToolAvailable(long toolId, boolean available) {
        jdbc.update("UPDATE tools SET available = ? WHERE id = ?", available ? 1 : 0, toolId);
    }

    public void closeRental(long rentalId) {
        jdbc.update("UPDATE rentals SET returned = 1 WHERE id = ?", rentalId);
    }
}

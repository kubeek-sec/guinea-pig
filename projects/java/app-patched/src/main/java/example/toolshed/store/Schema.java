package example.toolshed.store;

import javax.sql.DataSource;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/** Creates the tables on start-up and seeds the workshop once. */
@Configuration
public class Schema {

    private static final String DDL = """
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

    private static final Object[][] SEED_TOOLS = {
            {"Circular saw", "cutting", "190 mm blade, 1400 W", 12.5},
            {"Impact driver", "drilling", "18 V, two batteries", 8.0},
            {"Mitre saw", "cutting", "Sliding, 255 mm", 18.0},
            {"Heat gun", "finishing", "2000 W, variable", 5.5},
            {"Mortar mixer", "masonry", "1600 W, 140 mm paddle", 15.0},
    };

    private static final String[][] SEED_MEMBERS = {
            {"ada@toolshed.example", "Ada Mallory", "workshop-keeper", "staff"},
            {"jun@toolshed.example", "Jun Watanabe", "sawdust-season", "member"},
            {"pierre@toolshed.example", "Pierre Lefranc", "bench-grinder", "member"},
    };

    @Bean
    JdbcTemplate jdbcTemplate(DataSource dataSource) {
        return new JdbcTemplate(dataSource);
    }

    @Bean
    BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner initDatabase(JdbcTemplate jdbc, BCryptPasswordEncoder encoder) {
        return args -> {
            for (String statement : DDL.split(";")) {
                if (!statement.isBlank()) {
                    jdbc.execute(statement);
                }
            }
            Integer tools = jdbc.queryForObject("SELECT COUNT(*) FROM tools", Integer.class);
            if (tools != null && tools == 0) {
                for (Object[] t : SEED_TOOLS) {
                    jdbc.update("INSERT INTO tools (name, category, description, daily_rate) VALUES (?, ?, ?, ?)",
                            t[0], t[1], t[2], t[3]);
                }
                for (String[] m : SEED_MEMBERS) {
                    jdbc.update("INSERT INTO members (email, full_name, password, role) VALUES (?, ?, ?, ?)",
                            m[0], m[1], encoder.encode(m[2]), m[3]);
                }
            }
        };
    }
}

package example.toolshed;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Toolshed — the lending service of a neighbourhood workshop. */
@SpringBootApplication
public class ToolshedApplication {

    public static final String VERSION = "1.4.2";

    public static void main(String[] args) {
        SpringApplication.run(ToolshedApplication.class, args);
    }
}

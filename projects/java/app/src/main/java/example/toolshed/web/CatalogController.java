package example.toolshed.web;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import example.toolshed.ToolshedApplication;
import example.toolshed.store.Repositories;
import example.toolshed.store.Tool;

/** Browsing the tool catalogue. */
@RestController
public class CatalogController {

    private static final Set<String> SORTABLE = Set.of("name", "category", "daily_rate");

    private final Repositories repo;

    public CatalogController(Repositories repo) {
        this.repo = repo;
    }

    @GetMapping("/healthz")
    public Map<String, String> health() {
        return Map.of("status", "ok", "version", ToolshedApplication.VERSION);
    }

    @GetMapping(value = "/", produces = MediaType.TEXT_HTML_VALUE)
    public String home() {
        StringBuilder rows = new StringBuilder();
        for (Tool t : repo.topTools(20)) {
            rows.append("<tr><td>").append(HtmlUtils.htmlEscape(t.name()))
                .append("</td><td>").append(HtmlUtils.htmlEscape(t.category()))
                .append("</td><td>").append(String.format("%.2f", t.dailyRate()))
                .append(" &euro;</td><td>")
                .append(t.available() ? "on the rack" : "<span class=\"out\">out</span>")
                .append("</td></tr>\n");
        }
        return """
                <!doctype html>
                <html lang="en">
                <head><meta charset="utf-8"><title>Toolshed</title>
                <style>body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:48rem}
                table{border-collapse:collapse;width:100%%}th,td{border-bottom:1px solid #ddd;padding:.5rem;text-align:left}
                .out{color:#999}</style></head>
                <body><h1>Toolshed</h1><p>Tools the workshop lends to its members.</p>
                <table><tr><th>Tool</th><th>Category</th><th>Per day</th><th>Status</th></tr>
                %s
                </table><p><a href="/openapi.yml">API description</a></p></body></html>
                """.formatted(rows);
    }

    @GetMapping("/api/tools")
    public Map<String, List<Tool>> listTools(@RequestParam(defaultValue = "name") String sort) {
        if (!SORTABLE.contains(sort)) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "cannot sort on '" + sort + "'");
        }
        return Map.of("tools", repo.toolsOrderedBy(sort));
    }

    @GetMapping("/api/tools/search")
    public Map<String, Object> searchTools(@RequestParam(defaultValue = "") String q) {
        return Map.of("query", q, "tools", repo.searchTools(q));
    }

    @GetMapping("/api/tools/{id}")
    public Tool getTool(@PathVariable long id) {
        return repo.tool(id)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "no such tool"));
    }
}

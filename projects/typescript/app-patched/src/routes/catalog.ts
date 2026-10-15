// Browsing the tool catalogue.
import { Router } from "express";

import type { DB, Tool } from "../db";

const SORTABLE = new Set(["name", "category", "daily_rate"]);

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);
}

function homePage(tools: Tool[]): string {
  const rows = tools
    .map(
      (t) => `<tr><td>${escapeHtml(t.name)}</td><td>${escapeHtml(t.category)}</td>` +
        `<td>${t.daily_rate.toFixed(2)} &euro;</td>` +
        `<td>${t.available ? "on the rack" : '<span class="out">out</span>'}</td></tr>`,
    )
    .join("\n");
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Toolshed</title>
<style>body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:48rem}
table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid #ddd;padding:.5rem;text-align:left}
.out{color:#999}</style></head>
<body><h1>Toolshed</h1><p>Tools the workshop lends to its members.</p>
<table><tr><th>Tool</th><th>Category</th><th>Per day</th><th>Status</th></tr>
${rows}
</table><p><a href="/openapi.yml">API description</a></p></body></html>`;
}

export function catalogRoutes(db: DB): Router {
  const router = Router();

  router.get("/", (_req, res) => {
    const tools = db.prepare("SELECT * FROM tools ORDER BY name LIMIT 20").all() as Tool[];
    res.type("html").send(homePage(tools));
  });

  router.get("/api/tools", (req, res) => {
    const sort = String(req.query.sort ?? "name");
    if (!SORTABLE.has(sort)) {
      res.status(400).json({ error: `cannot sort on '${sort}'` });
      return;
    }
    const tools = db.prepare(`SELECT * FROM tools ORDER BY ${sort}`).all() as Tool[];
    res.json({ tools });
  });

  router.get("/api/tools/search", (req, res) => {
    const term = String(req.query.q ?? "");
    const tools = db
      .prepare("SELECT * FROM tools WHERE name LIKE ? OR description LIKE ?")
      .all(`%${term}%`, `%${term}%`) as Tool[];
    res.json({ query: term, tools });
  });

  router.get("/api/tools/:id", (req, res) => {
    const tool = db.prepare("SELECT * FROM tools WHERE id = ?").get(req.params.id) as Tool | undefined;
    if (!tool) {
      res.status(404).json({ error: "no such tool" });
      return;
    }
    res.json(tool);
  });

  return router;
}

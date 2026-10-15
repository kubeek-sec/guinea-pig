// Toolshed — the lending service of a neighbourhood workshop.
import fs from "node:fs";
import path from "node:path";

import express from "express";

import { open } from "./db";
import { catalogRoutes } from "./routes/catalog";
import { memberRoutes } from "./routes/members";
import { photoRoutes } from "./routes/photos";
import { rentalRoutes } from "./routes/rentals";

export const VERSION = "1.4.2";

const ROOT = path.resolve(__dirname, "..");

export function createApp() {
  const dbFile = process.env.TOOLSHED_DB ?? path.join(ROOT, "var", "toolshed.db");
  const uploadDir = process.env.TOOLSHED_UPLOADS ?? path.join(ROOT, "var", "uploads");
  fs.mkdirSync(uploadDir, { recursive: true });

  const db = open(dbFile);
  const app = express();
  app.use(express.json());

  app.get("/healthz", (_req, res) => {
    res.json({ status: "ok", version: VERSION });
  });
  app.get("/openapi.yml", (_req, res) => {
    res.type("application/yaml").sendFile(path.join(ROOT, "openapi.yml"));
  });

  app.use(catalogRoutes(db));
  app.use(memberRoutes(db));
  app.use(rentalRoutes(db));
  app.use(photoRoutes(db, uploadDir));
  return app;
}

if (require.main === module) {
  const port = Number(process.env.PORT ?? 8000);
  createApp().listen(port, "0.0.0.0", () => {
    console.log(`toolshed ${VERSION} listening on :${port}`);
  });
}

// Condition photos attached to a rental.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { Router } from "express";
import multer from "multer";

import { signedIn } from "../auth";
import type { DB } from "../db";

const ACCEPTED = new Set([".jpg", ".jpeg", ".png", ".webp"]);
const MAX_BYTES = 8 * 1024 * 1024;

export function photoRoutes(db: DB, uploadDir: string): Router {
  const router = Router();
  const upload = multer({ dest: uploadDir, limits: { fileSize: MAX_BYTES } });

  router.post("/api/photos", signedIn(db), upload.single("photo"), (req, res) => {
    if (!req.file) {
      res.status(400).json({ error: "no photo" });
      return;
    }
    const ext = path.extname(req.file.originalname).toLowerCase();
    if (!ACCEPTED.has(ext)) {
      fs.unlinkSync(req.file.path);
      res.status(400).json({ error: `${ext || "file"} not accepted` });
      return;
    }
    const name = `${crypto.randomBytes(16).toString("hex")}${ext}`;
    fs.renameSync(req.file.path, path.join(uploadDir, name));
    res.status(201).json({ name, owner: req.member!.email });
  });

  router.get("/api/photos/:name", (req, res) => {
    const name = path.basename(req.params.name);
    const file = path.join(uploadDir, name);
    if (!fs.existsSync(file)) {
      res.status(404).json({ error: "no such photo" });
      return;
    }
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.sendFile(file);
  });

  return router;
}

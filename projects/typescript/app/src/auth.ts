// Member sessions: bearer tokens signed with the instance key.
import type { NextFunction, Request, Response } from "express";

import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

import type { DB, Member } from "./db";

export const ALGORITHM = "HS256" as const;

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      member?: Member;
    }
  }
}

function signingKey(): string {
  const key = process.env.TOOLSHED_TOKEN_KEY;
  if (!key) throw new Error("TOOLSHED_TOKEN_KEY is not set");
  return key;
}

function ttl(): number {
  return Number(process.env.TOOLSHED_TOKEN_TTL ?? 3600);
}

export function issueToken(member: Member): string {
  return jwt.sign(
    { sub: String(member.id), email: member.email, role: member.role },
    signingKey(),
    { algorithm: ALGORITHM, expiresIn: ttl() },
  );
}

export function authenticate(db: DB, email: string, password: string): Member | null {
  const row = db.prepare("SELECT * FROM members WHERE email = ?").get(email) as Member | undefined;
  if (!row || !bcrypt.compareSync(password, row.password)) return null;
  return row;
}

export function currentMember(db: DB, req: Request): Member | null {
  const header = req.get("authorization") ?? "";
  if (!header.startsWith("Bearer ")) return null;
  try {
    const claims = jwt.verify(header.slice(7), signingKey(), {
      algorithms: [ALGORITHM],
    }) as jwt.JwtPayload;
    if (!claims.sub) return null;
    const row = db.prepare("SELECT * FROM members WHERE id = ?").get(claims.sub) as Member | undefined;
    return row ?? null;
  } catch {
    return null;
  }
}

export function signedIn(db: DB) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const member = currentMember(db, req);
    if (!member) {
      res.status(401).json({ error: "authentication required" });
      return;
    }
    req.member = member;
    next();
  };
}

export function staffOnly(req: Request, res: Response, next: NextFunction): void {
  if (req.member?.role !== "staff") {
    res.status(403).json({ error: "staff only" });
    return;
  }
  next();
}

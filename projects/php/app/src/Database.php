<?php

declare(strict_types=1);

namespace Toolshed;

use PDO;

/** SQLite access layer and the initial dataset of the workshop. */
final class Database
{
    private const DDL = <<<'SQL'
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
        SQL;

    private const SEED_TOOLS = [
        ['Circular saw', 'cutting', '190 mm blade, 1400 W', 12.5],
        ['Impact driver', 'drilling', '18 V, two batteries', 8.0],
        ['Mitre saw', 'cutting', 'Sliding, 255 mm', 18.0],
        ['Heat gun', 'finishing', '2000 W, variable', 5.5],
        ['Mortar mixer', 'masonry', '1600 W, 140 mm paddle', 15.0],
    ];

    private const SEED_MEMBERS = [
        ['ada@toolshed.example', 'Ada Mallory', 'workshop-keeper', 'staff'],
        ['jun@toolshed.example', 'Jun Watanabe', 'sawdust-season', 'member'],
        ['pierre@toolshed.example', 'Pierre Lefranc', 'bench-grinder', 'member'],
    ];

    public readonly PDO $pdo;

    public function __construct(string $file)
    {
        $dir = dirname($file);
        if (!is_dir($dir)) {
            mkdir($dir, 0o750, true);
        }
        $this->pdo = new PDO('sqlite:' . $file);
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        $this->initialise();
    }

    private function initialise(): void
    {
        $this->pdo->exec(self::DDL);
        if ((int) $this->pdo->query('SELECT COUNT(*) FROM tools')->fetchColumn() > 0) {
            return;
        }
        $tool = $this->pdo->prepare(
            'INSERT INTO tools (name, category, description, daily_rate) VALUES (?, ?, ?, ?)'
        );
        foreach (self::SEED_TOOLS as $row) {
            $tool->execute($row);
        }
        $member = $this->pdo->prepare(
            'INSERT INTO members (email, full_name, password, role) VALUES (?, ?, ?, ?)'
        );
        foreach (self::SEED_MEMBERS as [$email, $name, $password, $role]) {
            $member->execute([$email, $name, password_hash($password, PASSWORD_BCRYPT), $role]);
        }
    }
}

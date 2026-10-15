<?php

declare(strict_types=1);

namespace Toolshed;

use PDO;

/** Read and write access to the three tables of the workshop. */
final class Repositories
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    /** @return list<array<string, mixed>> */
    public function toolsOrderedBy(string $column): array
    {
        return $this->cast($this->pdo->query('SELECT * FROM tools ORDER BY ' . $column)->fetchAll());
    }

    /** @return list<array<string, mixed>> */
    public function topTools(int $limit): array
    {
        $statement = $this->pdo->prepare('SELECT * FROM tools ORDER BY name LIMIT ?');
        $statement->execute([$limit]);
        return $this->cast($statement->fetchAll());
    }

    /** @return list<array<string, mixed>> */
    public function searchTools(string $term): array
    {
        $statement = $this->pdo->prepare(
            'SELECT * FROM tools WHERE name LIKE ? OR description LIKE ?'
        );
        $like = '%' . $term . '%';
        $statement->execute([$like, $like]);
        return $this->cast($statement->fetchAll());
    }

    public function tool(int $id): ?array
    {
        $statement = $this->pdo->prepare('SELECT * FROM tools WHERE id = ?');
        $statement->execute([$id]);
        $row = $statement->fetch();
        return $row === false ? null : $this->castOne($row);
    }

    public function memberByEmail(string $email): ?array
    {
        $statement = $this->pdo->prepare('SELECT * FROM members WHERE email = ?');
        $statement->execute([$email]);
        $row = $statement->fetch();
        return $row === false ? null : $row;
    }

    public function member(int $id): ?array
    {
        $statement = $this->pdo->prepare('SELECT * FROM members WHERE id = ?');
        $statement->execute([$id]);
        $row = $statement->fetch();
        return $row === false ? null : $row;
    }

    /** @return list<array<string, mixed>> */
    public function rentalsOf(int $memberId): array
    {
        $statement = $this->pdo->prepare(
            'SELECT r.*, t.name AS tool_name FROM rentals r
             JOIN tools t ON t.id = r.tool_id
             WHERE r.member_id = ? ORDER BY r.taken_on DESC'
        );
        $statement->execute([$memberId]);
        return array_map([$this, 'castRental'], $statement->fetchAll());
    }

    public function rentalOf(int $rentalId, int $memberId): ?array
    {
        $statement = $this->pdo->prepare('SELECT * FROM rentals WHERE id = ? AND member_id = ?');
        $statement->execute([$rentalId, $memberId]);
        $row = $statement->fetch();
        return $row === false ? null : $this->castRental($row);
    }

    public function createRental(int $memberId, int $toolId, string $takenOn,
                                 string $dueOn, string $notes): int
    {
        $statement = $this->pdo->prepare(
            'INSERT INTO rentals (member_id, tool_id, taken_on, due_on, notes) VALUES (?, ?, ?, ?, ?)'
        );
        $statement->execute([$memberId, $toolId, $takenOn, $dueOn, $notes]);
        return (int) $this->pdo->lastInsertId();
    }

    public function setToolAvailable(int $toolId, bool $available): void
    {
        $statement = $this->pdo->prepare('UPDATE tools SET available = ? WHERE id = ?');
        $statement->execute([$available ? 1 : 0, $toolId]);
    }

    public function closeRental(int $rentalId): void
    {
        $statement = $this->pdo->prepare('UPDATE rentals SET returned = 1 WHERE id = ?');
        $statement->execute([$rentalId]);
    }

    private function cast(array $rows): array
    {
        return array_map([$this, 'castOne'], $rows);
    }

    private function castOne(array $row): array
    {
        $row['id'] = (int) $row['id'];
        $row['daily_rate'] = (float) $row['daily_rate'];
        $row['available'] = (bool) $row['available'];
        return $row;
    }

    private function castRental(array $row): array
    {
        $row['id'] = (int) $row['id'];
        $row['member_id'] = (int) $row['member_id'];
        $row['tool_id'] = (int) $row['tool_id'];
        $row['returned'] = (bool) $row['returned'];
        return $row;
    }
}

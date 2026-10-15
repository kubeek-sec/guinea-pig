<?php

declare(strict_types=1);

namespace Toolshed;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use RuntimeException;
use Throwable;

/** Issues and reads the bearer tokens of a member session. */
final class TokenService
{
    public const ALGORITHM = 'HS256';

    public function __construct(private readonly Repositories $repositories)
    {
    }

    private function signingKey(): string
    {
        $key = getenv('TOOLSHED_TOKEN_KEY');
        if ($key === false || $key === '') {
            throw new RuntimeException('TOOLSHED_TOKEN_KEY is not set');
        }
        return $key;
    }

    private function ttl(): int
    {
        $ttl = (int) (getenv('TOOLSHED_TOKEN_TTL') ?: 3600);
        return $ttl > 0 ? $ttl : 3600;
    }

    public function issue(array $member): string
    {
        $now = time();
        return JWT::encode([
            'sub' => (string) $member['id'],
            'email' => $member['email'],
            'role' => $member['role'],
            'iat' => $now,
            'exp' => $now + $this->ttl(),
        ], $this->signingKey(), self::ALGORITHM);
    }

    public function authenticate(string $email, string $password): ?array
    {
        $member = $this->repositories->memberByEmail($email);
        if ($member === null || !password_verify($password, $member['password'])) {
            return null;
        }
        return $member;
    }

    public function fromHeader(?string $authorization): ?array
    {
        if ($authorization === null || !str_starts_with($authorization, 'Bearer ')) {
            return null;
        }
        try {
            $claims = JWT::decode(substr($authorization, 7),
                new Key($this->signingKey(), self::ALGORITHM));
            return $this->repositories->member((int) $claims->sub);
        } catch (Throwable) {
            return null;
        }
    }
}

<?php

declare(strict_types=1);

namespace Toolshed;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;
use Slim\App as SlimApp;

/** Toolshed — the lending service of a neighbourhood workshop. */
final class App
{
    public const VERSION = '1.4.2';
    private const SORTABLE = ['name', 'category', 'daily_rate'];
    private const ACCEPTED = ['jpg', 'jpeg', 'png', 'webp'];
    private const PHOTO_TYPES = [
        'jpg' => 'image/jpeg',
        'jpeg' => 'image/jpeg',
        'png' => 'image/png',
        'webp' => 'image/webp',
    ];
    private const DEFAULT_DAYS = 7;
    private const MAX_PHOTO_BYTES = 8388608;

    public static function create(): SlimApp
    {
        $root = dirname(__DIR__);
        $dbFile = getenv('TOOLSHED_DB') ?: $root . '/var/toolshed.db';
        $uploads = getenv('TOOLSHED_UPLOADS') ?: $root . '/var/uploads';
        if (!is_dir($uploads)) {
            mkdir($uploads, 0o750, true);
        }

        $repositories = new Repositories((new Database($dbFile))->pdo);
        $tokens = new TokenService($repositories);

        $app = AppFactory::create();
        $app->addBodyParsingMiddleware();
        $app->addRoutingMiddleware();
        $app->addErrorMiddleware(false, true, true);

        self::catalogue($app, $repositories, $root);
        self::members($app, $repositories, $tokens);
        self::rentals($app, $repositories, $tokens);
        self::photos($app, $tokens, $uploads);
        return $app;
    }

    private static function json(Response $response, mixed $body, int $status = 200): Response
    {
        $response->getBody()->write((string) json_encode($body, JSON_UNESCAPED_SLASHES));
        return $response->withHeader('Content-Type', 'application/json')->withStatus($status);
    }

    private static function fail(Response $response, int $status, string $message): Response
    {
        return self::json($response, ['error' => $message], $status);
    }

    private static function catalogue(SlimApp $app, Repositories $repo, string $root): void
    {
        $app->get('/healthz', fn(Request $q, Response $r) =>
            self::json($r, ['status' => 'ok', 'version' => self::VERSION]));

        $app->get('/openapi.yml', function (Request $q, Response $r) use ($root): Response {
            $r->getBody()->write((string) file_get_contents($root . '/openapi.yml'));
            return $r->withHeader('Content-Type', 'application/yaml');
        });

        $app->get('/', function (Request $q, Response $r) use ($repo): Response {
            $rows = '';
            foreach ($repo->topTools(20) as $tool) {
                $rows .= sprintf(
                    "<tr><td>%s</td><td>%s</td><td>%.2f &euro;</td><td>%s</td></tr>\n",
                    htmlspecialchars((string) $tool['name'], ENT_QUOTES),
                    htmlspecialchars((string) $tool['category'], ENT_QUOTES),
                    $tool['daily_rate'],
                    $tool['available'] ? 'on the rack' : '<span class="out">out</span>'
                );
            }
            $r->getBody()->write(<<<HTML
                <!doctype html>
                <html lang="en">
                <head><meta charset="utf-8"><title>Toolshed</title>
                <style>body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:48rem}
                table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid #ddd;padding:.5rem;text-align:left}
                .out{color:#999}</style></head>
                <body><h1>Toolshed</h1><p>Tools the workshop lends to its members.</p>
                <table><tr><th>Tool</th><th>Category</th><th>Per day</th><th>Status</th></tr>
                {$rows}
                </table><p><a href="/openapi.yml">API description</a></p></body></html>
                HTML);
            return $r->withHeader('Content-Type', 'text/html');
        });

        $app->get('/api/tools', function (Request $q, Response $r) use ($repo): Response {
            $sort = (string) ($q->getQueryParams()['sort'] ?? 'name');
            if (!in_array($sort, self::SORTABLE, true)) {
                return self::fail($r, 400, "cannot sort on '{$sort}'");
            }
            return self::json($r, ['tools' => $repo->toolsOrderedBy($sort)]);
        });

        $app->get('/api/tools/search', function (Request $q, Response $r) use ($repo): Response {
            $term = (string) ($q->getQueryParams()['q'] ?? '');
            return self::json($r, ['query' => $term, 'tools' => $repo->searchTools($term)]);
        });

        $app->get('/api/tools/{id:[0-9]+}', function (Request $q, Response $r, array $args) use ($repo): Response {
            $tool = $repo->tool((int) $args['id']);
            return $tool === null ? self::fail($r, 404, 'no such tool') : self::json($r, $tool);
        });
    }

    private static function publicMember(array $member): array
    {
        return [
            'id' => (int) $member['id'],
            'email' => $member['email'],
            'full_name' => $member['full_name'],
            'role' => $member['role'],
        ];
    }

    private static function members(SlimApp $app, Repositories $repo, TokenService $tokens): void
    {
        $app->post('/api/session', function (Request $q, Response $r) use ($tokens): Response {
            $body = (array) ($q->getParsedBody() ?? []);
            $member = $tokens->authenticate((string) ($body['email'] ?? ''), (string) ($body['password'] ?? ''));
            if ($member === null) {
                return self::fail($r, 401, 'bad credentials');
            }
            return self::json($r, ['token' => $tokens->issue($member), 'role' => $member['role']]);
        });

        $app->get('/api/members/me', function (Request $q, Response $r) use ($tokens): Response {
            $member = $tokens->fromHeader($q->getHeaderLine('Authorization') ?: null);
            return $member === null
                ? self::fail($r, 401, 'authentication required')
                : self::json($r, self::publicMember($member));
        });

        $app->get('/api/members/{id:[0-9]+}', function (Request $q, Response $r, array $args) use ($repo, $tokens): Response {
            $caller = $tokens->fromHeader($q->getHeaderLine('Authorization') ?: null);
            if ($caller === null) {
                return self::fail($r, 401, 'authentication required');
            }
            if ($caller['role'] !== 'staff') {
                return self::fail($r, 403, 'staff only');
            }
            $member = $repo->member((int) $args['id']);
            return $member === null
                ? self::fail($r, 404, 'no such member')
                : self::json($r, self::publicMember($member));
        });
    }

    private static function rentals(SlimApp $app, Repositories $repo, TokenService $tokens): void
    {
        $app->get('/api/rentals', function (Request $q, Response $r) use ($repo, $tokens): Response {
            $member = $tokens->fromHeader($q->getHeaderLine('Authorization') ?: null);
            if ($member === null) {
                return self::fail($r, 401, 'authentication required');
            }
            return self::json($r, ['rentals' => $repo->rentalsOf((int) $member['id'])]);
        });

        $app->post('/api/rentals', function (Request $q, Response $r) use ($repo, $tokens): Response {
            $member = $tokens->fromHeader($q->getHeaderLine('Authorization') ?: null);
            if ($member === null) {
                return self::fail($r, 401, 'authentication required');
            }
            $body = (array) ($q->getParsedBody() ?? []);
            $tool = $repo->tool((int) ($body['tool_id'] ?? 0));
            if ($tool === null) {
                return self::fail($r, 404, 'no such tool');
            }
            if (!$tool['available']) {
                return self::fail($r, 409, 'already out');
            }
            $days = (int) ($body['days'] ?? 0);
            $days = $days > 0 ? $days : self::DEFAULT_DAYS;
            $today = new \DateTimeImmutable('today');
            $due = $today->modify("+{$days} days");
            $id = $repo->createRental((int) $member['id'], (int) $tool['id'],
                $today->format('Y-m-d'), $due->format('Y-m-d'), (string) ($body['notes'] ?? ''));
            $repo->setToolAvailable((int) $tool['id'], false);
            return self::json($r, ['id' => $id, 'due_on' => $due->format('Y-m-d')], 201);
        });

        $app->post('/api/rentals/{id:[0-9]+}/return', function (Request $q, Response $r, array $args) use ($repo, $tokens): Response {
            $member = $tokens->fromHeader($q->getHeaderLine('Authorization') ?: null);
            if ($member === null) {
                return self::fail($r, 401, 'authentication required');
            }
            $rental = $repo->rentalOf((int) $args['id'], (int) $member['id']);
            if ($rental === null) {
                return self::fail($r, 404, 'no such rental');
            }
            $repo->closeRental((int) $rental['id']);
            $repo->setToolAvailable((int) $rental['tool_id'], true);
            return self::json($r, ['status' => 'returned']);
        });
    }

    private static function photos(SlimApp $app, TokenService $tokens, string $uploads): void
    {
        $app->post('/api/photos', function (Request $q, Response $r) use ($tokens, $uploads): Response {
            $member = $tokens->fromHeader($q->getHeaderLine('Authorization') ?: null);
            if ($member === null) {
                return self::fail($r, 401, 'authentication required');
            }
            $photo = ($q->getUploadedFiles()['photo'] ?? null);
            if ($photo === null || $photo->getError() !== UPLOAD_ERR_OK) {
                return self::fail($r, 400, 'no photo');
            }
            if (($photo->getSize() ?? 0) > self::MAX_PHOTO_BYTES) {
                return self::fail($r, 400, 'photo too large');
            }
            $ext = strtolower(pathinfo((string) $photo->getClientFilename(), PATHINFO_EXTENSION));
            if (!in_array($ext, self::ACCEPTED, true)) {
                return self::fail($r, 400, ($ext === '' ? 'file' : '.' . $ext) . ' not accepted');
            }
            $name = bin2hex(random_bytes(16)) . '.' . $ext;
            $photo->moveTo($uploads . '/' . $name);
            return self::json($r, ['name' => $name, 'owner' => $member['email']], 201);
        });

        $app->get('/api/photos/{name}', function (Request $q, Response $r, array $args) use ($uploads): Response {
            $file = $uploads . '/' . basename((string) $args['name']);
            if (!is_file($file)) {
                return self::fail($r, 404, 'no such photo');
            }
            $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
            $r->getBody()->write((string) file_get_contents($file));
            return $r
                ->withHeader('Content-Type', self::PHOTO_TYPES[$ext] ?? 'application/octet-stream')
                ->withHeader('X-Content-Type-Options', 'nosniff');
        });
    }
}

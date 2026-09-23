<?php
// IAM-Local — Serveur OAuth 2.0 / OIDC
// Requiert includes/functions.php

if (!function_exists('iam_oauth_current_key')) {

function iam_oauth_openssl_config(): ?string
{
    static $candidates = null;
    if ($candidates === null) {
        $candidates = [];
        $bin = defined('PHP_BINDIR') ? PHP_BINDIR : '';
        if ($bin !== '') {
            $candidates[] = $bin . '/extras/ssl/openssl.cnf';
            $candidates[] = $bin . '/../extras/ssl/openssl.cnf';
            $candidates[] = $bin . '/../php/openssl.cnf';
        }
        $candidates[] = 'C:/wamp64/scripts/httpsFiles/openssl.cnf';
        $candidates[] = 'C:/wamp64/bin/apache/apache2.4.65/conf/openssl.cnf';
        // Balayage des distributions PHP WAMP
        foreach (glob('C:/wamp64/bin/php/*/extras/ssl/openssl.cnf') ?: [] as $p) $candidates[] = $p;
        $candidates = array_values(array_unique($candidates));
    }
    foreach ($candidates as $p) {
        if (is_file($p)) return $p;
    }
    return null;
}

function iam_oauth_new_rsa_key(): array
{
    $opts = ['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA];
    $cfg = iam_oauth_openssl_config();
    if ($cfg !== null) $opts['config'] = $cfg;
    $res = @openssl_pkey_new($opts);
    if (!$res) {
        $opts2 = ['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA];
        $res = @openssl_pkey_new($opts2);
    }
    if (!$res) {
        throw new RuntimeException('Impossible de générer la clé RSA OAuth (openssl_pkey_new).');
    }
    openssl_pkey_export($res, $privPem, null, $opts);
    $pub = openssl_pkey_get_details($res);
    if (!$pub) throw new RuntimeException('Détails de la clé RSA indisponibles.');
    return [$privPem, $pub['key']];
}

function iam_oauth_current_key(): array
{
    $db = db();
    $row = $db->query('SELECT * FROM oauth_keys WHERE active = 1 ORDER BY id DESC LIMIT 1')->fetch();
    if ($row) return $row;

    // Génération de la première clé
    [$privPem, $pubPem] = iam_oauth_new_rsa_key();
    $kid = bin2hex(random_bytes(8));
    $stmt = $db->prepare('INSERT INTO oauth_keys (kid, priv_pem, pub_pem, alg, active) VALUES (?, ?, ?, ?, 1)');
    $stmt->execute([$kid, $privPem, $pubPem, 'RS256']);
    return $db->query('SELECT * FROM oauth_keys WHERE kid = ' . $db->quote($kid))->fetch();
}

function iam_oauth_rotate_key(): array
{
    $db = db();
    $db->exec('UPDATE oauth_keys SET active = 0');
    [$privPem, $pubPem] = iam_oauth_new_rsa_key();
    $kid = bin2hex(random_bytes(8));
    $db->prepare('INSERT INTO oauth_keys (kid, priv_pem, pub_pem, alg, active) VALUES (?, ?, ?, ?, 1)')
       ->execute([$kid, $privPem, $pubPem, 'RS256']);
    return $db->query('SELECT * FROM oauth_keys WHERE kid = ' . $db->quote($kid))->fetch();
}

function iam_oauth_jwks(): array
{
    $db = db();
    $keys = [];
    foreach ($db->query('SELECT kid, pub_pem, alg FROM oauth_keys ORDER BY active DESC, id DESC') as $row) {
        $details = openssl_pkey_get_details(openssl_pkey_get_public($row['pub_pem']));
        $keys[] = [
            'kty' => 'RSA',
            'use' => 'sig',
            'kid' => $row['kid'],
            'alg' => $row['alg'],
            'n'   => base64_url_encode($details['rsa']['n']),
            'e'   => base64_url_encode($details['rsa']['e']),
        ];
    }
    return $keys;
}

function iam_oauth_jwt_rs256(array $payload, array $key, int $ttl): string
{
    $header = base64_url_encode(json_encode(['alg' => 'RS256', 'typ' => 'JWT', 'kid' => $key['kid']]));
    $payload['exp'] = time() + $ttl;
    $payload['iat'] = time();
    $body = base64_url_encode(json_encode($payload));
    openssl_sign("$header.$body", $sig, openssl_pkey_get_private($key['priv_pem']), OPENSSL_ALGO_SHA256);
    return "$header.$body." . base64_url_encode($sig);
}

function iam_oauth_jwt_decode(string $token): ?array
{
    $parts = explode('.', $token);
    if (count($parts) !== 3) return null;
    [$h, $b, $s] = $parts;
    $header = json_decode(base64_url_decode($h), true);
    if (!$header || ($header['alg'] ?? '') !== 'RS256') return null;
    $db = db();
    $stmt = $db->prepare('SELECT priv_pem, pub_pem, alg FROM oauth_keys WHERE kid = ?');
    $stmt->execute([$header['kid'] ?? '']);
    $key = $stmt->fetch();
    if (!$key) return null;
    $ok = openssl_verify("$h.$b", base64_url_decode($s), openssl_pkey_get_public($key['pub_pem']), OPENSSL_ALGO_SHA256);
    if ($ok !== 1) return null;
    $payload = json_decode(base64_url_decode($b), true);
    if (!$payload) return null;
    if (isset($payload['exp']) && $payload['exp'] < time()) return null;
    return $payload;
}

function iam_oauth_client(?string $clientId): ?array
{
    if ($clientId === null || $clientId === '') return null;
    $db = db();
    $stmt = $db->prepare('SELECT * FROM oauth_clients WHERE client_id = ? LIMIT 1');
    $stmt->execute([$clientId]);
    return $stmt->fetch() ?: null;
}

function iam_oauth_client_redirects(array $client): array
{
    $uris = json_decode($client['redirect_uris'] ?? '[]', true);
    return is_array($uris) ? array_values($uris) : [];
}

function iam_oauth_redirect_ok(array $client, string $redirectUri): bool
{
    foreach (iam_oauth_client_redirects($client) as $allowed) {
        if ($redirectUri === $allowed) return true;
        // Tolérance pragmatique : même origine + même chemin, query variante
        $a = parse_url($allowed);
        $b = parse_url($redirectUri);
        if (($a['scheme'] ?? '') === ($b['scheme'] ?? '')
            && ($a['host'] ?? '') === ($b['host'] ?? '')
            && (($a['path'] ?? '') === ($b['path'] ?? ''))) {
            return true;
        }
    }
    return false;
}

function iam_oauth_client_auth(): ?array
{
    // Authentification du client : Basic (Authorization) ou POST (client_id + client_secret)
    $raw = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (preg_match('/Basic\s+(.+)$/i', $raw, $m)) {
        $dec = base64_decode(trim($m[1]));
        if ($dec !== false && strpos($dec, ':') !== false) {
            [$c, $s] = explode(':', $dec, 2);
            return [trim($c), trim($s)];
        }
    }
    if (isset($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'])) {
        return [trim($_SERVER['PHP_AUTH_USER']), trim($_SERVER['PHP_AUTH_PW'])];
    }
    $c = trim($_POST['client_id'] ?? '');
    $s = trim($_POST['client_secret'] ?? '');
    return ($c !== '') ? [$c, $s] : null;
}

function iam_oauth_issue_tokens(array $client, int $userId, string $scope, ?string $nonce = null, int $authTime = 0): array
{
    $db = db();
    $key = iam_oauth_current_key();
    $accessTtl = 900;
    $scope = trim($scope) ?: 'profile';

    $access = iam_oauth_jwt_rs256([
        'iss' => IAM_BASE_URL,
        'sub' => (string) $userId,
        'aud' => $client['client_id'],
        'scope' => $scope,
    ], $key, $accessTtl);

    $refreshToken = bin2hex(random_bytes(40));
    $stmt = $db->prepare('INSERT INTO refresh_tokens (user_id, token, client_id, scope, expires_at) VALUES (?, ?, ?, ?, UTC_TIMESTAMP() + INTERVAL 30 DAY)');
    $stmt->execute([$userId, $refreshToken, $client['client_id'], $scope]);

    $result = [
        'access_token'  => $access,
        'token_type'    => 'Bearer',
        'expires_in'    => $accessTtl,
        'scope'         => $scope,
        'refresh_token' => $refreshToken,
    ];

    if (in_array('openid', explode(' ', $scope), true)) {
        $user = iam_find_user_by_id($userId);
        $idPayload = [
            'iss' => IAM_BASE_URL,
            'sub' => (string) $userId,
            'aud' => $client['client_id'],
            'auth_time' => $authTime ?: time(),
        ];
        if ($nonce) $idPayload['nonce'] = $nonce;
        if ($user) {
            $idPayload['name']  = trim(($user['first_name'] ?? '') . ' ' . ($user['last_name'] ?? ''));
            $idPayload['given_name'] = $user['first_name'] ?? '';
            $idPayload['family_name'] = $user['last_name'] ?? '';
            $idPayload['email'] = $user['email'] ?? '';
            $idPayload['email_verified'] = true;
            $idPayload['preferred_username'] = $user['username'] ?? '';
        }
        $result['id_token'] = iam_oauth_jwt_rs256($idPayload, $key, $accessTtl);
    }
    return $result;
}

function iam_oauth_error(int $status, string $error, string $desc = ''): void
{
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode(['error' => $error, 'error_description' => $desc]);
    exit;
}

} // fin if !function_exists
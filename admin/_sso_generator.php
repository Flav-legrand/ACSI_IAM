<?php
// IAM-Local — Génération & déploiement automatique de l'intégration SSO
// Utilisé par admin/apps.php : crée un fichier "garde" PHP autonome dans
// l'application cible + un .htaccess (auto_prepend_file) afin que toute
// page de l'application exige une authentification IAM (également quand
// l'utilisateur accède directement par le lien de l'application).

function iam_app_code_slug(string $code): string
{
    return strtolower(trim(preg_replace('/[^a-zA-Z0-9]+/', '-', $code), '-'));
}

/**
 * Auto-migration : ajoute la colonne applications.bridge_config si absente
 * (base installée avant cette fonctionnalité).
 */
function iam_ensure_app_bridge_column(PDO $db): void
{
    $stmt = $db->prepare("SELECT COUNT(*) FROM information_schema.columns
        WHERE table_schema = DATABASE() AND table_name = 'applications' AND column_name = 'bridge_config'");
    $stmt->execute();
    if ((int) $stmt->fetchColumn() === 0) {
        $db->exec("ALTER TABLE applications ADD COLUMN bridge_config TEXT NULL COMMENT 'Pont de session locale (JSON)'");
    }
}

/**
 * Normalise la configuration « pont de session locale » stockée dans
 * applications.bridge_config (JSON).
 */
function iam_bridge_config(array $app): array
{
    $cfg = json_decode((string) ($app['bridge_config'] ?? ''), true);
    if (!is_array($cfg)) $cfg = [];

    $ident = static function ($s, int $max = 64): string {
        return substr(preg_replace('/[^A-Za-z0-9_]+/', '', (string) $s), 0, $max);
    };

    return [
        'enabled'      => !empty($cfg['enabled']),
        'db_host'      => substr(preg_replace('/[^A-Za-z0-9.\-_:]+/', '', (string) ($cfg['db_host'] ?? 'localhost')), 0, 120),
        'db_port'      => substr(preg_replace('/[^0-9]+/', '', (string) ($cfg['db_port'] ?? '3306')), 0, 6),
        'db_name'      => substr(preg_replace('/[^A-Za-z0-9_\-]+/', '', (string) ($cfg['db_name'] ?? '')), 0, 64),
        'db_user'      => substr(preg_replace('/[^A-Za-z0-9_.\-]+/', '', (string) ($cfg['db_user'] ?? 'root')), 0, 64),
        'db_pass'      => (string) ($cfg['db_pass'] ?? ''),
        'table'        => $ident($cfg['table'] ?? '', 64),
        'match_iam'    => in_array($matchIam = ($cfg['match_iam'] ?? 'username'), ['username', 'email', 'matricule'], true) ? $matchIam : 'username',
        'match_local'  => $ident($cfg['match_local'] ?? '', 64),
        'key_id'       => $ident($cfg['key_id'] ?? 'id', 64),
        'key_login'    => $ident($cfg['key_login'] ?? '', 64),
        'key_nom'      => $ident($cfg['key_nom'] ?? '', 64),
        'key_role'     => $ident($cfg['key_role'] ?? '', 64),
        'role_source'  => ($cfg['role_source'] ?? 'local') === 'map' ? 'map' : 'local',
        'role_default' => substr(preg_replace('/[^A-Za-z0-9_\-\. ]+/', '', (string) ($cfg['role_default'] ?? '')), 0, 64),
        'role_map'     => (array) ($cfg['role_map'] ?? []),
        'auto_create'  => !empty($cfg['auto_create']),
        'create_role'  => $ident($cfg['create_role'] ?? '', 64),
        'create_status'=> $ident($cfg['create_status'] ?? '', 32),
        'create_pwd_col'   => $ident($cfg['create_pwd_col'] ?? 'mot_de_passe', 64),
        'create_status_col'=> $ident($cfg['create_status_col'] ?? 'statut', 64),
    ];
}

/**
 * Résout le chemin local (disque) à partir de l'URL de l'application.
 * Uniquement si l'application est hébergée sur le même serveur/document root.
 */
function iam_local_path_from_url(string $url, string $docRoot): ?string
{
    $parts = parse_url($url);
    if (!$parts || empty($parts['host']) || empty($parts['path'])) return null;

    $h = strtolower(trim($parts['host'], '[]'));
    $serverHost = strtolower(trim(preg_replace('/:\d+$/', '', $_SERVER['HTTP_HOST'] ?? ''), '[]'));

    $allowed = ['localhost', '127.0.0.1', '::1'];
    if ($serverHost !== '') {
        $allowed[] = $serverHost;
    }
    if (!in_array($h, $allowed, true)) return null;

    $path = rtrim($parts['path'], '/');
    if ($path === '') return null;

    $docRoot = rtrim(str_replace('\\', '/', $docRoot), '/');
    return $docRoot . $path;
}

/**
 * Construit le contenu du fichier « garde » SSO autonome pour une application.
 */
function iam_build_guard_content(array $app): string
{
    $code     = iam_app_code_slug($app['code'] ?? 'app');
    $base     = rtrim(IAM_BASE_URL, '/');
    $appUrl   = rtrim($app['url'] ?? '', '/');
    $appName  = $app['name'] ?? $app['code'] ?? 'Application';
    $ssoPrompt = ((int) ($app['sso_prompt'] ?? 1)) === 1 ? 'true' : 'false';
    $date     = date('Y-m-d H:i:s');

    // ── Pont de session locale (optionnel) ─────────────────────
    $bridgeCfg     = iam_bridge_config($app);
    $bridgeDefs    = '';
    $bridgeCall    = '';
    if ($bridgeCfg['enabled'] && $bridgeCfg['table'] !== '' && $bridgeCfg['db_name'] !== '') {
        $host = $bridgeCfg['db_host'];
        $port = $bridgeCfg['db_port'];
        $dbName = $bridgeCfg['db_name'];
        $dbUser = $bridgeCfg['db_user'];
        $dbPass = addslashes($bridgeCfg['db_pass']);
        $table   = $bridgeCfg['table'];
        $matchIam = $bridgeCfg['match_iam'];
        $matchLocal = $bridgeCfg['match_local'];
        $keyId    = $bridgeCfg['key_id'];
        $keyLogin = $bridgeCfg['key_login'];
        $keyNom   = $bridgeCfg['key_nom'];
        $keyRole  = $bridgeCfg['key_role'];
        $roleSource = $bridgeCfg['role_source'];
        $roleDefault = $bridgeCfg['role_default'];
        $autoCreate    = $bridgeCfg['auto_create'] ? 'true' : 'false';
        $createRole    = $bridgeCfg['create_role'];
        $createStatus  = $bridgeCfg['create_status'];
        $createPwdCol  = $bridgeCfg['create_pwd_col'];
        $createStatusCol = $bridgeCfg['create_status_col'];

        $mapLines = [];
        foreach ($bridgeCfg['role_map'] as $k => $v) {
            $mapLines[] = "            '" . addslashes((string) $k) . "' => '" . addslashes((string) $v) . "',";
        }
        $mapPhp = $mapLines ? implode("\n", $mapLines) : "            '" . addslashes($roleDefault) . "' => '" . addslashes($roleDefault) . "',";
        if ($mapPhp === '') $mapPhp = "            'admin' => 'admin',";

        $bridgeDefs = <<<DEFS

/* ============ Pont : session locale de l'application ============ */
/* Renseigne la session interne de l'application (user_id, user_login,
   user_nom, user_role) après authentification IAM. Configuré dans
   Administration > Applications → « Pont de session locale ». */
define('IAM_BRIDGE_ENABLED', true);
define('IAM_BRIDGE_DB_HOST',   '{$host}');
define('IAM_BRIDGE_DB_PORT',   '{$port}');
define('IAM_BRIDGE_DB_NAME',   '{$dbName}');
define('IAM_BRIDGE_DB_USER',   '{$dbUser}');
define('IAM_BRIDGE_DB_PASS',   '{$dbPass}');
define('IAM_BRIDGE_TABLE',     '{$table}');
define('IAM_BRIDGE_MATCH_IAM','{$matchIam}');
define('IAM_BRIDGE_MATCH_LOCAL','{$matchLocal}');
define('IAM_BRIDGE_KEY_USER_ID','{$keyId}');
define('IAM_BRIDGE_KEY_USER_LOGIN','{$keyLogin}');
define('IAM_BRIDGE_KEY_USER_NOM','{$keyNom}');
define('IAM_BRIDGE_KEY_USER_ROLE','{$keyRole}');
define('IAM_BRIDGE_ROLE_SOURCE','{$roleSource}');
define('IAM_BRIDGE_ROLE_DEFAULT','{$roleDefault}');
define('IAM_BRIDGE_AUTO_CREATE',   {$autoCreate});
define('IAM_BRIDGE_CREATE_ROLE',   '{$createRole}');
define('IAM_BRIDGE_CREATE_STATUS', '{$createStatus}');
define('IAM_BRIDGE_CREATE_PWD_COL','{$createPwdCol}');
define('IAM_BRIDGE_CREATE_STATUS_COL','{$createStatusCol}');

if (!function_exists('iam_sso_bridge_local_session')) {
    function iam_sso_bridge_local_session(array \$user, array \$roles = []): void
    {
        try {
            \$dsn = 'mysql:host=' . IAM_BRIDGE_DB_HOST . ';port=' . IAM_BRIDGE_DB_PORT . ';dbname=' . IAM_BRIDGE_DB_NAME . ';charset=utf8mb4';
            \$pdo = new PDO(\$dsn, IAM_BRIDGE_DB_USER, IAM_BRIDGE_DB_PASS, [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_TIMEOUT            => 5,
            ]);

            \$needle = IAM_BRIDGE_MATCH_IAM === 'email'    ? (\$user['email'] ?? '')
                     : (IAM_BRIDGE_MATCH_IAM === 'matricule' ? (\$user['matricule'] ?? '')
                     : (\$user['username'] ?? ''));
            if (\$needle === '') {
                \$_SESSION['iam_bridge_error'] = 'Champ de correspondance IAM vide (IAM_BRIDGE_MATCH_IAM).';
                return;
            }

            \$sql = 'SELECT * FROM `' . IAM_BRIDGE_TABLE . '` WHERE `' . IAM_BRIDGE_MATCH_LOCAL . '` = :needle LIMIT 1';
            \$st  = \$pdo->prepare(\$sql);
            \$st->execute([':needle' => \$needle]);
            \$row = \$st->fetch();

            if (!\$row) {
                if (IAM_BRIDGE_AUTO_CREATE) {
                    // Auto-création du compte local : le username IAM sert d'identifiant,
                    // le nom vient de l'IAM et le mot de passe est aléatoire (SSO uniquement,
                    // le formulaire interne de l'application ne pourra pas servir).
                    \$name = trim((string) (\$user['first_name'] ?? '') . ' ' . (string) (\$user['last_name'] ?? ''));
                    if (\$name === '') { \$name = (string) (\$user['email'] ?? ''); }
                    if (\$name === '') { \$name = \$needle; }

                    \$cols = ['`' . IAM_BRIDGE_MATCH_LOCAL . '`'];
                    \$hld  = [':needle'];
                    \$prms = [':needle' => \$needle];

                    if (IAM_BRIDGE_KEY_USER_NOM !== '') {
                        \$cols[] = '`' . IAM_BRIDGE_KEY_USER_NOM . '`';
                        \$hld[]  = ':nom';
                        \$prms[':nom'] = \$name;
                    }
                    if (IAM_BRIDGE_KEY_USER_ROLE !== '' && IAM_BRIDGE_CREATE_ROLE !== '') {
                        \$cols[] = '`' . IAM_BRIDGE_KEY_USER_ROLE . '`';
                        \$hld[]  = ':role';
                        \$prms[':role'] = IAM_BRIDGE_CREATE_ROLE;
                    }
                    if (IAM_BRIDGE_CREATE_STATUS !== '' && IAM_BRIDGE_CREATE_STATUS_COL !== '') {
                        \$cols[] = '`' . IAM_BRIDGE_CREATE_STATUS_COL . '`';
                        \$hld[]  = ':st';
                        \$prms[':st'] = IAM_BRIDGE_CREATE_STATUS;
                    }
                    if (IAM_BRIDGE_CREATE_PWD_COL !== '') {
                        \$cols[] = '`' . IAM_BRIDGE_CREATE_PWD_COL . '`';
                        \$hld[]  = ':pwd';
                        \$prms[':pwd'] = password_hash(bin2hex(random_bytes(32)), PASSWORD_DEFAULT);
                    }

                    \$sql = 'INSERT INTO `' . IAM_BRIDGE_TABLE . '` (' . implode(', ', \$cols) . ') VALUES (' . implode(', ', \$hld) . ')';
                    \$pdo->prepare(\$sql)->execute(\$prms);

                    \$st2 = \$pdo->prepare('SELECT * FROM `' . IAM_BRIDGE_TABLE . '` WHERE `' . IAM_BRIDGE_MATCH_LOCAL . '` = :needle LIMIT 1');
                    \$st2->execute([':needle' => \$needle]);
                    \$row = \$st2->fetch();
                    if (!\$row) {
                        \$_SESSION['iam_bridge_error'] = 'Compte créé mais relecture impossible (' . IAM_BRIDGE_TABLE . ').';
                        return;
                    }
                    \$_SESSION['iam_bridge_hint'] = 'Compte local créé automatiquement pour « ' . \$needle . ' » (rôle ' . IAM_BRIDGE_CREATE_ROLE . ').';
                } else {
                    \$_SESSION['iam_bridge_error'] = 'SSO réussi mais aucun utilisateur local « ' . \$needle . ' » (' . IAM_BRIDGE_TABLE . '.' . IAM_BRIDGE_MATCH_LOCAL . ').';
                    return;
                }
            }

            if (IAM_BRIDGE_KEY_USER_ID !== '')    \$_SESSION['user_id']    = (string) (\$row[IAM_BRIDGE_KEY_USER_ID] ?? '');
            if (IAM_BRIDGE_KEY_USER_LOGIN !== '') \$_SESSION['user_login'] = (string) (\$row[IAM_BRIDGE_KEY_USER_LOGIN] ?? '');
            if (IAM_BRIDGE_KEY_USER_NOM !== '')   \$_SESSION['user_nom']   = (string) (\$row[IAM_BRIDGE_KEY_USER_NOM] ?? '');

            if (IAM_BRIDGE_ROLE_SOURCE === 'local') {
                if (IAM_BRIDGE_KEY_USER_ROLE !== '') {
                    \$_SESSION['user_role'] = (string) (\$row[IAM_BRIDGE_KEY_USER_ROLE] ?? '');
                }
            } else {
                \$map = [
{$mapPhp}
                ];
                \$role = IAM_BRIDGE_ROLE_DEFAULT;
                foreach ((array) \$roles as \$r) {
                    \$code = \$r['code'] ?? (is_string(\$r) ? \$r : '');
                    if (isset(\$map[\$code])) { \$role = \$map[\$code]; break; }
                }
                \$_SESSION['user_role'] = \$role;
            }

            unset(\$_SESSION['iam_bridge_error']);
        } catch (\Throwable \$e) {
            \$_SESSION['iam_bridge_error'] = \$e->getMessage();
        }
    }
}
DEFS;

        $bridgeCall = "\n                if (IAM_BRIDGE_ENABLED) {\n                    iam_sso_bridge_local_session(\$data['user'] ?? [], \$data['roles'] ?? []);\n                }";
    }

    return <<<PHP
<?php
/**
 * IAM-Local — Intégration SSO automatique
 * ========================================
 * Application : {$appName} ({$code})
 * Généré le {$date} par l'interface d'administration IAM-Local.
 *
 * Ce fichier garantit que TOUTE page PHP de l'application est protégée :
 *   - accès direct par le lien => redirection vers l'IAM pour vous connecter,
 *   - après authentification => retour automatique sur la page demandée.
 *
 * Il est normalement chargé automatiquement via le .htaccess du dossier
 * (auto_prepend_file). Vous pouvez aussi l'inclure manuellement en tête
 * de chaque page :  require_once __DIR__ . '/iam-sso-{$code}.php';
 *
 * NE PAS MODIFIER à la main : régénérez-le depuis Administration > Applications.
 */

if (!defined('IAM_BASE_URL')) {
    define('IAM_BASE_URL', '{$base}');
}
define('IAM_APP_CODE',    '{$code}');
define('IAM_APP_NAME',    '{$appName}');
define('IAM_APP_URL',     '{$appUrl}');
define('IAM_APP_SESSION', 'iam_app_{$code}');
define('IAM_APP_SSO_PROMPT', {$ssoPrompt});

/* ============ Session isolée de l'application ============ */
if (!function_exists('iam_sso_session_start')) {
    function iam_sso_session_start(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_name(IAM_APP_SESSION);
            ini_set('session.cookie_httponly', '1');
            ini_set('session.use_strict_mode', '1');
            session_start();
        }
    }
}

/* ============ Validation du jeton auprès de l'IAM ============ */
if (!function_exists('iam_sso_validate_token')) {
    function iam_sso_validate_token(string \$token): ?array
    {
        \$ch = curl_init();
        curl_setopt_array(\$ch, [
            CURLOPT_URL            => IAM_BASE_URL . '/api/sso/validate.php',
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => json_encode(['token' => \$token, 'app_code' => IAM_APP_CODE]),
            CURLOPT_HTTPHEADER     => ['Content-Type: application/json', 'Accept: application/json'],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);
        \$body = curl_exec(\$ch);
        \$code = curl_getinfo(\$ch, CURLINFO_HTTP_CODE);
        curl_close(\$ch);
        if (\$body === false || \$code !== 200) return null;
        \$data = json_decode((string) \$body, true);
        return is_array(\$data) && empty(\$data['error']) ? \$data : null;
    }
}

/* ============ Données utilisateur locales ============ */
if (!function_exists('iam_sso_user')) {
    function iam_sso_user(): ?array
    {
        iam_sso_session_start();
        return \$_SESSION['iam_app_user'] ?? null;
    }
}

if (!function_exists('iam_sso_authenticated')) {
    function iam_sso_authenticated(): bool
    {
        iam_sso_session_start();
        return !empty(\$_SESSION['iam_app_authenticated']);
    }
}

if (!function_exists('iam_sso_has_permission')) {
    function iam_sso_has_permission(string \$code): bool
    {
        iam_sso_session_start();
        return in_array(\$code, \$_SESSION['iam_app_permissions'] ?? [], true);
    }
}

if (!function_exists('iam_sso_logout')) {
    function iam_sso_logout(): void
    {
        iam_sso_session_start();
        \$login = IAM_BASE_URL . '/logout.php';
        session_destroy();
        header('Location: ' . \$login);
        exit;
    }
}

/* ============ Garde principale ============ */
if (!function_exists('iam_sso_guard')) {
    function iam_sso_guard(): void
    {
        iam_sso_session_start();

        // 1) Retour de l'IAM avec un jeton à usage unique
        if (isset(\$_GET['sso_token']) && \$_GET['sso_token'] !== '') {
            \$data = iam_sso_validate_token((string) \$_GET['sso_token']);
            if (\$data) {
                session_regenerate_id(true);
                \$_SESSION['iam_app_authenticated'] = true;
                \$_SESSION['iam_app_user']         = \$data['user'] ?? \$data;
                \$_SESSION['iam_app_roles']        = \$data['roles'] ?? [];
                \$_SESSION['iam_app_permissions']  = \$data['permissions'] ?? [];
                \$_SESSION['iam_app_is_admin']     = !empty(\$data['is_global_admin']);
                \$_SESSION['iam_app_expires']      = time() + 3600;
                \$_SESSION['iam_app_login_time']   = time();{$bridgeCall}

                // Retirer uniquement le jeton de l'URL puis recharger proprement
                \$qs = \$_SERVER['REQUEST_URI'] ?? '';
                \$clean = strtok(\$qs, '?') ?: '/';
                if (strpos(\$qs, '?') !== false) {
                    \$params = [];
                    parse_str((string) parse_url(\$qs, PHP_URL_QUERY), \$params);
                    unset(\$params['sso_token']);
                    if (\$params) {
                        \$clean .= '?' . http_build_query(\$params);
                    }
                }
                header('Location: ' . \$clean);
                exit;
            }
            // Jeton invalide => on repart vers la connexion IAM
        }

        // 2) Déjà authentifié dans cette application ?
        if (iam_sso_authenticated()) {
            return;
        }

        // 3) Sinon, redirection vers l'IAM puis retour automatique
        if (isset(\$_SESSION['iam_app_last_url'])) {
            \$current = \$_SESSION['iam_app_last_url'];
        } else {
            \$current = (isset(\$_SERVER['HTTPS']) && \$_SERVER['HTTPS'] !== 'off' ? 'https' : 'http')
                      . '://' . \$_SERVER['HTTP_HOST'] . \$_SERVER['REQUEST_URI'];
        }

        header('Location: ' . IAM_BASE_URL . '/sso/authorize.php'
             . '?app=' . rawurlencode(IAM_APP_CODE)
             . '&return=' . rawurlencode(\$current)
             . (IAM_APP_SSO_PROMPT ? '&prompt=login' : ''));
        exit;
    }
}

{$bridgeDefs}
/* ============ Exécution immédiate ============ */
iam_sso_guard();
PHP;
}

/**
 * Déploie le fichier garde + .htaccess dans le dossier local de l'app.
 * Retourne un assoc: status (deployed|not_local|not_found|readonly|htaccess_guard)
 */
function iam_deploy_sso(array $app): array
{
    $code   = iam_app_code_slug($app['code'] ?? 'app');
    $guardFile = 'iam-sso-' . $code . '.php';
    $docRoot   = $_SERVER['DOCUMENT_ROOT'] ?? '';
    $localPath = iam_local_path_from_url((string) ($app['url'] ?? ''), (string) $docRoot);

    if ($localPath === null) {
        return ['status' => 'not_local',  'guard_file' => $guardFile, 'path' => null,
                'message' => 'Application hébergée ailleurs que localhost : déploiement manuel requis (voir « Télécharger »).'];
    }
    if (!is_dir($localPath)) {
        return ['status' => 'not_found',  'guard_file' => $guardFile, 'path' => $localPath,
                'message' => "Le dossier local « $localPath » est introuvable. Vérifiez l'URL de l'application."];
    }
    if (!is_writable($localPath)) {
        return ['status' => 'readonly',   'guard_file' => $guardFile, 'path' => $localPath,
                'message' => "Le dossier local « $localPath » n'est pas inscriptible."];
    }

    // 1) Écrire le fichier garde
    $guardPath = $localPath . '/' . $guardFile;
    if (@file_put_contents($guardPath, iam_build_guard_content($app)) === false) {
        return ['status' => 'write_error', 'guard_file' => $guardFile, 'path' => $localPath,
                'message' => "Impossible d'écrire « $guardPath »."];
    }

    // 2) .htaccess : activer auto_prepend_file (protège TOUTES les pages)
    $disableGuard = false;
    $line = '<IfModule mod_php.c>' . "\n"
          . 'php_value auto_prepend_file "' . addslashes($guardPath) . '"' . "\n"
          . '</IfModule>';
    $htPath = $localPath . '/.htaccess';

    if (file_exists($htPath)) {
        $ht = (string) @file_get_contents($htPath);
        if (strpos($ht, 'iam-sso-' . $code . '.php') !== false) {
            // Déjà déployé : on resynchronise le contenu du garde
            return ['status' => 'deployed', 'guard_file' => $guardFile, 'path' => $guardPath,
                    'message' => 'Intégration déjà active. Fichier garde resynchronisé.'];
        }
        // Ne pas casser un .htaccess applicatif existant : on le sauvegarde
        @copy($htPath, $htPath . '.iam-backup-' . date('YmdHis'));
        $ht .= "\n\n# ── IAM-Local : Protection SSO automatique (généré) ──\n" . $line . "\n";
        if (@file_put_contents($htPath, $ht) === false) {
            $disableGuard = true;
        }
    } else {
        $ht = "# === IAM-Local — Protection SSO automatique (généré) ===\n"
            . "# Ne pas supprimer si l'application doit exiger une connexion IAM.\n"
            . $line . "\n";
        if (@file_put_contents($htPath, $ht) === false) {
            $disableGuard = true;
        }
    }

    if ($disableGuard) {
        return ['status' => 'htaccess_error', 'guard_file' => $guardFile, 'path' => $guardPath,
                'message' => "Le fichier garde a été créé, mais impossible d'écrire « $htPath ». Activez manuellement auto_prepend_file."];
    }

    return ['status' => 'deployed', 'guard_file' => $guardFile, 'path' => $guardPath,
            'message' => 'Intégration SSO automatique déployée : l\'accès direct au lien de l\'application redirigera vers l\'IAM.'];
}
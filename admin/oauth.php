<?php
require_once __DIR__ . '/_guard.php';
require_once __DIR__ . '/../includes/oauth.php';

$db  = db();
$msg = '';
$type = 'success';
$err = '';

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf'] ?? '')) {
        $err = 'Session expirée. Réessayez.';
    } else {
        $action = $_POST['action'] ?? '';
        switch ($action) {
            case 'create_client':
                $name  = trim($_POST['name'] ?? '');
                $uris  = array_values(array_filter(array_map('trim', preg_split('/\r\n|\r|\n/', $_POST['redirect_uris'] ?? '')), fn($u) => $u !== ''));
                $grants = trim($_POST['grant_types'] ?? 'authorization_code');
                $scope  = trim($_POST['scope'] ?? 'openid profile email');
                if ($name === '' || empty($uris)) {
                    $err = 'Nom et au moins une URI de redirection sont obligatoires.';
                } else {
                    $clientId = 'iam.' . bin2hex(random_bytes(8));
                    $secret   = bin2hex(random_bytes(32));
                    // Conserver en clair exactement une fois (affiché au créateur) puis stocker le hash
                    $db->prepare("INSERT INTO oauth_clients (client_id, client_secret_hash, name, redirect_uris, grant_types, scope, active) VALUES (?, ?, ?, ?, ?, ?, 1)")
                       ->execute([$clientId, password_hash($secret, PASSWORD_BCRYPT), $name, json_encode($uris, JSON_UNESCAPED_UNICODE), $grants, $scope]);
                    setcookie('iam_oauth_secret_once', "secret:$clientId:$secret", 0, '/');
                    iam_audit('oauth_client_created', "Client OAuth créé: $name", $iamAdmin['id'], $iamAdmin['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
                    $msg = "Client créé : $clientId";
                }
                break;

            case 'toggle_client':
                $db->prepare('UPDATE oauth_clients SET active = IF(active=1,0,1) WHERE id = ?')->execute([(int) ($_POST['id'] ?? 0)]);
                $msg = 'Client mis à jour.';
                break;

            case 'delete_client':
                $db->prepare('DELETE FROM oauth_clients WHERE id = ?')->execute([(int) ($_POST['id'] ?? 0)]);
                $msg = 'Client supprimé.';
                break;

            case 'rotate_key':
                iam_oauth_rotate_key();
                iam_audit('oauth_key_rotated', 'Rotation de la clé de signature OIDC', $iamAdmin['id'], $iamAdmin['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
                $msg = 'Clé de signature OIDC remplacée (les anciens jetons restent valides jusqu’à expiration).';
                break;
        }
    }
}

$clients = $db->query('SELECT * FROM oauth_clients ORDER BY name')->fetchAll();
$keys = $db->query('SELECT kid, alg, active, created_at FROM oauth_keys ORDER BY id DESC')->fetchAll();

$pageTitle = 'OAuth 2.0 / OIDC';
$active = 'oauth';
include __DIR__ . '/_header.php';
?>
<?php if ($err): ?><div class="alert alert-danger"><?php echo htmlspecialchars($err); ?></div><?php endif; ?>
<?php if ($msg): ?><div class="alert alert-success"><?php echo htmlspecialchars($msg); ?></div><?php endif; ?>

<?php
$freshSecret = $_COOKIE['iam_oauth_secret_once'] ?? '';
if ($freshSecret !== '' && strpos($freshSecret, 'secret:') === 0) {
    [, $freshCid, $freshVal] = explode(':', $freshSecret, 3);
    echo '<div class="alert alert-info"><strong>Copiez le secret maintenant :</strong> il ne sera plus jamais affiché.<br>';
    echo '<span class="mono" style="display:inline-block; margin-top:8px; padding:8px 12px; background:#f1f5f9; border-radius:6px;">Client ID : ' . htmlspecialchars($freshCid) . '<br>Client secret : ' . htmlspecialchars($freshVal) . '</span></div>';
    setcookie('iam_oauth_secret_once', '', time() - 3600, '/');
}
?>

<div class="card">
    <div class="card-body">
        <div class="d-flex justify-between align-center mb-3">
            <div class="card-title">Clients OAuth (« applications tierces »)</div>
            <button class="btn btn-primary" onclick="document.getElementById('clientModal').style.display='block'"><i class="fas fa-plus"></i> Nouveau client</button>
        </div>
        <div class="table-wrap">
            <table class="table">
                <tr><th>Nom</th><th>client_id</th><th>URI de redirection</th><th>Grants</th><th>Statut</th><th>Actions</th></tr>
                <?php if (empty($clients)): ?>
                    <tr><td colspan="6" class="text-center text-muted">Aucun client OAuth. Créez-en un pour qu'une application utilise OAuth 2.0 / OIDC (ex : Flutter, Python, Angular).</td></tr>
                <?php else: foreach ($clients as $c): ?>
                    <tr>
                        <td><strong><?php echo htmlspecialchars($c['name']); ?></strong></td>
                        <td><code><?php echo htmlspecialchars($c['client_id']); ?></code></td>
                        <td style="max-width:320px;"><?php echo nl2br(htmlspecialchars(implode("\n", json_decode($c['redirect_uris'] ?? '[]', true) ?: []))); ?></td>
                        <td><small><?php echo htmlspecialchars($c['grant_types']); ?></small></td>
                        <td><span class="badge badge-<?php echo (int) $c['active'] === 1 ? 'success' : 'muted'; ?>"><?php echo (int) $c['active'] === 1 ? 'actif' : 'inactif'; ?></span></td>
                        <td>
                            <form method="POST" style="display:inline;">
                                <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                <input type="hidden" name="action" value="toggle_client">
                                <input type="hidden" name="id" value="<?php echo (int) $c['id']; ?>">
                                <button class="btn btn-outline btn-sm"><?php echo (int) $c['active'] === 1 ? '<i class="fas fa-pause"></i>' : '<i class="fas fa-play"></i>'; ?></button>
                            </form>
                            <form method="POST" style="display:inline;" onsubmit="return confirm('Supprimer ce client OAuth ?');">
                                <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                <input type="hidden" name="action" value="delete_client">
                                <input type="hidden" name="id" value="<?php echo (int) $c['id']; ?>">
                                <button class="btn btn-danger btn-sm"><i class="fas fa-trash"></i></button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; endif; ?>
            </table>
        </div>
    </div>
</div>

<div class="card mt-3">
    <div class="card-body">
        <div class="d-flex justify-between align-center">
            <div class="card-title">Clés de signature OIDC (JWKS)</div>
            <form method="POST" onsubmit="return confirm('Remplacer la clé de signature ? Les anciens jetons restent validables jusqu’à expiration.');">
                <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <input type="hidden" name="action" value="rotate_key">
                <button class="btn btn-outline btn-sm"><i class="fas fa-rotate"></i> Rotation de clé</button>
            </form>
        </div>
        <table class="table mt-2">
            <tr><th>kid</th><th>Algorithme</th><th>Statut</th><th>Créée le</th></tr>
            <?php foreach ($keys as $k): ?>
                <tr>
                    <td><code><?php echo htmlspecialchars($k['kid']); ?></code></td>
                    <td><?php echo htmlspecialchars($k['alg']); ?></td>
                    <td><span class="badge badge-<?php echo (int) $k['active'] === 1 ? 'success' : 'muted'; ?>"><?php echo (int) $k['active'] === 1 ? 'active (signature)' : 'ancienne (validation)'; ?></span></td>
                    <td><?php echo htmlspecialchars($k['created_at']); ?></td>
                </tr>
            <?php endforeach; ?>
        </table>
        <p class="text-muted" style="margin-bottom:0;">JWKS : <code><?php echo htmlspecialchars(IAM_BASE_URL); ?>/api/oauth/jwks.php</code> — Découverte : <code>/.well-known/openid-configuration</code></p>
    </div>
</div>

<div id="clientModal" style="display:none; position:fixed; inset:0; background:rgba(15,23,42,.55); z-index:1000;" onclick="if(event.target===this)this.style.display='none';">
    <div style="max-width:560px; margin:40px auto; background:#fff; border-radius:14px; padding:26px;">
        <h3 style="margin-top:0;">Nouveau client OAuth</h3>
        <form method="POST">
            <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <input type="hidden" name="action" value="create_client">
            <div class="form-group"><label>Nom de l'application *</label><input type="text" name="name" class="form-control" required placeholder="ex : App mobile Flutter ME"></div>
            <div class="form-group">
                <label>URI de redirection (une par ligne) *</label>
                <textarea name="redirect_uris" class="form-control" rows="3" required placeholder="http://localhost:8000/callback">http://localhost:8000/callback</textarea>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label>Type de flux autorisés</label>
                    <select name="grant_types" class="form-control">
                        <option value="authorization_code">Authorization Code + PKCE (recommandé)</option>
                        <option value="authorization_code,client_credentials">Code + machine-to-machine</option>
                        <option value="client_credentials">Machine-to-machine uniquement</option>
                    </select>
                </div>
                <div class="form-group"><label>Scopes</label><input type="text" name="scope" class="form-control" value="openid profile email"></div>
            </div>
            <div class="d-flex gap-2">
                <button type="submit" class="btn btn-primary"><i class="fas fa-save"></i> Créer</button>
                <button type="button" class="btn btn-outline" onclick="document.getElementById('clientModal').style.display='none';">Annuler</button>
            </div>
        </form>
    </div>
</div>
<?php include __DIR__ . '/_footer.php'; ?>
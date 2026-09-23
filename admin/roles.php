<?php
require_once __DIR__ . '/_guard.php';

$db  = db();
$msg = '';
$err = '';

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ── Actions ───────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf'] ?? '')) {
        $err = 'Session expirée.';
    } else {
        $action = $_POST['action'] ?? '';
        switch ($action) {
            case 'create_role':
                $name = trim($_POST['name'] ?? '');
                $code = strtolower(trim(preg_replace('/[^a-zA-Z0-9_]+/', '_', $_POST['code'] ?? '')));
                $desc = trim($_POST['description'] ?? '');
                if ($name === '' || $code === '') { $err = 'Nom et code obligatoires.'; }
                else {
                    $db->prepare('INSERT INTO roles (name, code, description) VALUES (?, ?, ?)')->execute([$name, $code, $desc]);
                    iam_audit('role_created', "Rôle créé: $name", $iamAdmin['id'], $iamAdmin['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
                    $msg = 'Rôle créé.';
                }
                break;

            case 'edit_role':
                $rid = (int) ($_POST['id'] ?? 0);
                $db->prepare('UPDATE roles SET name=?, description=? WHERE id=? AND is_system=0')
                   ->execute([trim($_POST['name'] ?? ''), trim($_POST['description'] ?? ''), $rid]);
                // Permissions
                $db->prepare('DELETE FROM role_permissions WHERE role_id = ?')->execute([$rid]);
                if (isset($_POST['perms']) && is_array($_POST['perms'])) {
                    $stmt = $db->prepare('INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)');
                    foreach ($_POST['perms'] as $pid) $stmt->execute([$rid, (int) $pid]);
                }
                iam_audit('role_updated', "Rôle modifié (permissions)", $iamAdmin['id'], $iamAdmin['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
                $msg = 'Rôle et permissions mis à jour.';
                break;

            case 'delete_role':
                $rid = (int) ($_POST['id'] ?? 0);
                $stmt = $db->prepare('SELECT is_system FROM roles WHERE id = ?');
                $stmt->execute([$rid]);
                $role = $stmt->fetch();
                if (!$role) $err = 'Rôle introuvable.';
                elseif ($role['is_system']) $err = 'Impossible de supprimer un rôle système.';
                else {
                    $db->prepare('DELETE FROM roles WHERE id = ?')->execute([$rid]);
                    $msg = 'Rôle supprimé.';
                }
                break;

            case 'save_policy':
                $policy = iam_get_password_policy();
                foreach (['min_length' => 8, 'history' => 5, 'expiration_days' => 90, 'lockout_threshold' => 5, 'lockout_minutes' => 30] as $key => $def) {
                    $v = max(0, (int) ($_POST[$key] ?? $def));
                    $db->prepare("UPDATE password_policy SET $key = ? WHERE id = 1")->execute([$v]);
                }
                foreach (['require_upper', 'require_lower', 'require_digit', 'require_special'] as $key) {
                    $db->prepare("UPDATE password_policy SET $key = ? WHERE id = 1")->execute([isset($_POST[$key]) ? 1 : 0]);
                }
                iam_audit('policy_updated', 'Politique de mot de passe modifiée', $iamAdmin['id'], $iamAdmin['email'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '');
                $msg = 'Politique de mot de passe enregistrée.';
                break;
        }
    }
}

// ── Données ───────────────────────────────────────────────
$roles = $db->query('SELECT * FROM roles ORDER BY name')->fetchAll();
$apps  = $db->query('SELECT * FROM applications WHERE active = 1 ORDER BY name')->fetchAll();
$perms = $db->query('SELECT p.*, a.name AS app_name FROM permissions p LEFT JOIN applications a ON a.id = p.application_id ORDER BY a.name, p.name')->fetchAll();

// Regrouper les permissions par application
$permsByApp = [];
foreach ($perms as $p) {
    $permsByApp[$p['application_id']][] = $p;
}

// Permissions par rôle
$rolePerms = [];
foreach ($roles as $r) {
    $stmt = $db->prepare('SELECT permission_id FROM role_permissions WHERE role_id = ?');
    $stmt->execute([$r['id']]);
    $rolePerms[$r['id']] = array_map('intval', array_column($stmt->fetchAll(), 'permission_id'));
}

$policy = iam_get_password_policy();
$pageTitle = 'Rôles & permissions';
$active = 'roles';
include __DIR__ . '/_header.php';
?>
<?php if ($err): ?><div class="alert alert-danger"><?php echo htmlspecialchars($err); ?></div><?php endif; ?>
<?php if ($msg): ?><div class="alert alert-success"><?php echo htmlspecialchars($msg); ?></div><?php endif; ?>

<div class="cards-grid">
    <?php foreach ($roles as $r): ?>
        <div class="card">
            <div class="card-body">
                <div class="d-flex justify-between align-center">
                    <div class="card-title" style="margin:0;">
                        <?php if ($r['is_system']): ?><i class="fas fa-star" title="Rôle système"></i><?php endif; ?>
                        <?php echo htmlspecialchars($r['name']); ?>
                        <span class="badge badge-muted mono"><?php echo htmlspecialchars($r['code']); ?></span>
                    </div>
                    <?php if (!$r['is_system']): ?>
                        <div class="d-flex gap-2">
                            <button class="btn btn-outline btn-sm" onclick="document.getElementById('roleFormBody-<?php echo (int) $r['id']; ?>').style.display='block'; document.getElementById('roleBtn-<?php echo (int) $r['id']; ?>').style.display='none';">Permissions</button>
                            <form method="POST" onsubmit="return confirm('Supprimer ce rôle ?');">
                                <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                <input type="hidden" name="action" value="delete_role">
                                <input type="hidden" name="id" value="<?php echo (int) $r['id']; ?>">
                                <button class="btn btn-danger btn-sm"><i class="fas fa-trash"></i></button>
                            </form>
                        </div>
                    <?php endif; ?>
                </div>
                <p class="text-muted mb-2"><?php echo htmlspecialchars($r['description'] ?? ''); ?></p>

                <?php if ($r['is_system']): ?>
                    <div style="margin-top:8px;">
                        <span class="text-muted" style="font-size:12px;"><?php echo count($rolePerms[$r['id']]); ?> permissions attachées</span>
                    </div>
                <?php else: ?>
                    <div id="roleBtn-<?php echo (int) $r['id']; ?>">
                        <span class="text-muted" style="font-size:12px;"><?php echo count($rolePerms[$r['id']]); ?> permissions attachées &middot; <strong><?php echo (int) $db->query('SELECT COUNT(*) FROM user_roles WHERE role_id = ' . (int) $r['id'])->fetchColumn(); ?></strong> attributions</span>
                    </div>
                    <div id="roleFormBody-<?php echo (int) $r['id']; ?>" style="display:none; margin-top:10px;">
                        <form method="POST">
                            <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                            <input type="hidden" name="action" value="edit_role">
                            <input type="hidden" name="id" value="<?php echo (int) $r['id']; ?>">
                            <div class="form-group"><label>Nom</label><input type="text" name="name" class="form-control" value="<?php echo htmlspecialchars($r['name']); ?>"></div>
                            <div class="form-group"><label>Description</label><textarea name="description" class="form-control" rows="2"><?php echo htmlspecialchars($r['description'] ?? ''); ?></textarea></div>
                            <div class="card-title">Permissions</div>
                            <?php foreach ($permsByApp as $appId => $appPerms): ?>
                                <div class="mb-2">
                                    <strong style="font-size:13px;"><?php echo htmlspecialchars($permsByApp[$appId][0]['app_name'] ?? 'Général'); ?></strong>
                                    <div class="d-flex flex-wrap gap-2 mt-1">
                                        <?php foreach ($appPerms as $p): ?>
                                            <label style="display:inline-flex; align-items:center; gap:5px; background:#f8fafc; border:1px solid var(--border); padding:6px 10px; border-radius:8px; font-size:12.5px;">
                                                <input type="checkbox" name="perms[]" value="<?php echo (int) $p['id']; ?>" <?php echo in_array((int) $p['id'], $rolePerms[$r['id']], true) ? 'checked' : ''; ?>>
                                                <?php echo htmlspecialchars($p['name']); ?>
                                            </label>
                                        <?php endforeach; ?>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                            <div class="d-flex gap-2 mt-2">
                                <button type="submit" class="btn btn-primary btn-sm"><i class="fas fa-save"></i> Enregistrer</button>
                                <button type="button" class="btn btn-outline btn-sm" onclick="this.closest('div').parentElement.style.display='none'; document.getElementById('roleBtn-<?php echo (int) $r['id']; ?>').style.display='block';">Fermer</button>
                            </div>
                        </form>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    <?php endforeach; ?>

    <div class="card">
        <div class="card-body">
            <div class="card-title">Créer un rôle</div>
            <form method="POST">
                <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <input type="hidden" name="action" value="create_role">
                <div class="form-group"><label>Nom du rôle</label><input type="text" name="name" class="form-control" required placeholder="ex : Superviseur Paie"></div>
                <div class="form-group"><label>Code</label><input type="text" name="code" class="form-control" required placeholder="ex : superviseur_paie"></div>
                <div class="form-group"><label>Description</label><textarea name="description" class="form-control" rows="2"></textarea></div>
                <button type="submit" class="btn btn-success"><i class="fas fa-plus"></i> Créer</button>
            </form>
        </div>
    </div>
</div>
<?php include __DIR__ . '/_footer.php'; ?>
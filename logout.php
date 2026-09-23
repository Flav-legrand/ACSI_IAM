<?php
// IAM-Local — Déconnexion
require_once __DIR__ . '/includes/functions.php';

iam_session_start();

$redirect = IAM_BASE_URL . '/login.php?msg=logout';
if (isset($_GET['redirect'])) {
    $r = rawurldecode($_GET['redirect']);
    if (preg_match('#^https?://#i', $r)) $redirect = $r;
}

$ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

if (!empty($_SESSION['iam_user'])) {
    iam_audit('logout', 'Déconnexion du portail IAM', (int) $_SESSION['iam_user']['id'], $_SESSION['iam_user']['email'] ?? '', $ip, $ua);
}

iam_session_destroy();
header('Location: ' . $redirect);
exit;
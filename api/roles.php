<?php
// IAM-Local — API REST : GET /api/roles.php
require_once __DIR__ . '/../includes/functions.php';

$user = api_require_auth();
$db = db();
$stmt = $db->query('SELECT id, name, code, description, is_system FROM roles ORDER BY name');
$roles = $stmt->fetchAll();
api_json_response(['roles' => $roles]);

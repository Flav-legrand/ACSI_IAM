<?php
// IAM-Local — Configuration centrale
define('IAM_BASE_URL',   'http://localhost/IAM-Local');
define('IAM_NAME',       'IAM ACSI');
define('IAM_VERSION',    '1.0.0');
define('IAM_TAGLINE',    'Portail d acces securise aux applications');

// Base de données
define('DB_HOST',  'localhost');
define('DB_USER',  'root');
define('DB_PASS',  '');
define('DB_NAME',  'iam_local');
define('DB_PORT',  '3306');

// Session PHP
define('SESSION_LIFETIME',   3600);    // durée max de vie d'une session IAM en secondes
define('IDLE_TIMEOUT',       1800);    // inactivité max (secondes) avant déconnexion auto
define('SESSION_COOKIE_NAME','iam_session');

// SSO
define('SSO_TOKEN_LIFETIME', 60);      // durée de vie d'un jeton SSO (secondes)

// JWT (clé secrète pour signer les jetons — régénérée à l'installation)
define('IAM_JWT_SECRET', '72f71a59bbed8fdf902cd3bffb11e6610d7a2fb8f18e05c22cde76cc951b6f1b');

// MFA
define('OTP_LENGTH',    6);
define('OTP_LIFETIME',  300);          // 5 min pour valider l'OTP
define('OTP_MAX_TRIES', 5);
define('MFA_FORCE_ALL', true);         // exigent une vérification par e-mail pour tous à la connexion

// Anti force brute
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOCKOUT_MINUTES',    30);

// SMTP (optionnel pour MFA email)
define('SMTP_HOST',  'smtp.gmail.com');
define('SMTP_PORT',  465);
define('SMTP_USER',  '');
define('SMTP_PASS',  '');
define('SMTP_FROM',  '');
define('SMTP_FROM_NAME', 'IAM ACSI');

// OAuth2 (envoi MFA via Gmail ou Outlook — créer une app OAuth chez le fournisseur)
define('OAUTH_GOOGLE_CLIENT_ID',     '');
define('OAUTH_GOOGLE_CLIENT_SECRET', '');
define('OAUTH_MICROSOFT_CLIENT_ID',     '');
define('OAUTH_MICROSOFT_CLIENT_SECRET', '');

// Upload
define('UPLOAD_DIR', __DIR__ . '/uploads/');
define('MAX_UPLOAD_SIZE', 2 * 1024 * 1024); // 2 Mo
-- ============================================================
--  IAM-LOCAL — Données système (obligatoires, vierges de tout métier)
--  Placeholders remplacés par l'installateur :
--    {{BASE_URL}}, {{ADMIN_USERNAME}}, {{ADMIN_EMAIL}}, {{ADMIN_PHONE}},
--    {{ADMIN_FIRST_NAME}}, {{ADMIN_LAST_NAME}}, {{ADMIN_MATRICULE}},
--    {{ADMIN_PASSWORD_HASH}}
--  Les données métier optionnelles (démonstration) sont dans seed-demo.sql.
-- ============================================================

USE iam_local;

-- ------------------------------------------------------------
-- Politique de mot de passe par défaut
-- ------------------------------------------------------------
INSERT INTO password_policy (id, min_length, require_upper, require_lower, require_digit, require_special, history, expiration_days, lockout_threshold, lockout_minutes, session_lifetime, idle_timeout)
VALUES (1, 8, 1, 1, 1, 1, 5, 90, 5, 30, 3600, 1800);

-- ------------------------------------------------------------
-- Application "IAM — Administration" (système, non supprimable)
-- ------------------------------------------------------------
INSERT INTO applications (id, code, name, description, url, client_id, redirect_uri, scopes, color, icon, active, is_system) VALUES
(3, 'iam-admin', 'IAM — Administration', 'Console d''administration de la plateforme IAM',
   '{{BASE_URL}}/admin', NULL, NULL, 'openid profile email roles', '#6f42c1', 'fa-shield-halved', 1, 1);

-- ------------------------------------------------------------
-- Rôles génériques de la plateforme
-- ------------------------------------------------------------
INSERT INTO roles (id, name, code, description, is_system) VALUES
(1, 'Administrateur',       'admin',            'Accès complet à toutes les applications', 1),
(2, 'Directeur',            'directeur',        'Direction et validation', 0),
(3, 'Gestionnaire',         'gestionnaire',     'Gestion des ressources', 0),
(4, 'Chef de Service',      'chef_service',     'Supervision d''un service', 0),
(5, 'Agent',                'agent',            'Accès utilisateur standard', 0),
(6, 'Auditeur',             'auditeur',         'Consultation et audit', 0);

-- ------------------------------------------------------------
-- Permissions — Application IAM Admin (3)
-- ------------------------------------------------------------
INSERT INTO permissions (id, application_id, name, code, description) VALUES
(15, 3, 'Administrer l''IAM', 'iam.admin', 'Administration complète de la plateforme IAM'),
(16, 3, 'Gérer les utilisateurs', 'users.manage', 'Créer, modifier, supprimer des utilisateurs'),
(17, 3, 'Gérer les rôles', 'roles.manage', 'Gérer les rôles et permissions'),
(18, 3, 'Voir les journaux', 'audit.view', 'Consulter le journal d''audit');

-- ------------------------------------------------------------
-- Rôle Administrateur : toutes les permissions IAM
-- ------------------------------------------------------------
INSERT INTO role_permissions (role_id, permission_id) VALUES
(1, 15), (1, 16), (1, 17), (1, 18);

-- ------------------------------------------------------------
-- Utilisateur administrateur par défaut (créé par l'installateur)
-- ------------------------------------------------------------
INSERT INTO users (id, username, email, phone, password_hash, first_name, last_name, matricule, organization_id, status, mfa_enabled, must_change_password)
VALUES (1, '{{ADMIN_USERNAME}}', '{{ADMIN_EMAIL}}', '{{ADMIN_PHONE}}',
        '{{ADMIN_PASSWORD_HASH}}',
        '{{ADMIN_FIRST_NAME}}', '{{ADMIN_LAST_NAME}}', '{{ADMIN_MATRICULE}}', NULL, 'active', 0, 0);

INSERT INTO password_history (user_id, password_hash)
VALUES (1, '{{ADMIN_PASSWORD_HASH}}');

-- ------------------------------------------------------------
-- Rôle de l'administrateur sur l'application IAM
-- ------------------------------------------------------------
INSERT INTO user_roles (user_id, role_id, application_id) VALUES
(1, 1, 3);
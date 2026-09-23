-- ============================================================
--  IAM-LOCAL — Données de DÉMONSTRATION (import optionnel)
--  Exemples : organisation ADEN, applications Gestion Présence / Salaire.
--  À remplacer librement par les vraies applications.
--  Toutes ces applications sont marquées is_system=0 : l'admin
--  peut les supprimer depuis l'interface.
-- ============================================================

USE iam_local;

-- ------------------------------------------------------------
-- Organisation de démonstration : ADEN (exemple)
-- ------------------------------------------------------------
INSERT INTO organizations (id, parent_id, name, code, type) VALUES
(1, NULL, 'ADEN — Agence de Développement de l''Économie Numérique', 'ADEN', 'direction_generale'),
(2, 1,    'Direction des Ressources Humaines', 'DRH', 'direction'),
(3, 2,    'Service Gestion du Personnel', 'SGP', 'service'),
(4, 2,    'Service des Salaires & Paie', 'SSP', 'service'),
(5, 1,    'Direction des Systèmes d''Information', 'DSI', 'direction'),
(6, 5,    'Service Support & Sécurité', 'SSS', 'service');

-- Raccorder l'administrateur par défaut à la DSI (démo)
UPDATE users SET organization_id = 5 WHERE id = 1;

-- ------------------------------------------------------------
-- Applications de démonstration
-- ------------------------------------------------------------
INSERT INTO applications (id, code, name, description, url, client_id, redirect_uri, scopes, color, icon, active, is_system) VALUES
(1, 'gestion-presence', 'Gestion des Présences', 'Suivi et gestion des présences du personnel',
   '{{BASE_URL}}/GestionPresnceAdenIAM', 'iam-native-presence', '{{BASE_URL}}/GestionPresnceAdenIAM/sso-login.php',
   'openid profile email roles', '#1a7f37', 'fa-clock', 1, 0),
(2, 'gestion-salaire', 'Gestion des Salaires', 'Élaboration, validation et paiement des salaires',
   '{{BASE_URL}}/GestionSalaireAden', 'iam-native-salaire', '{{BASE_URL}}/GestionSalaireAden/sso-login.php',
   'openid profile email roles', '#1a237e', 'fa-money-bill-wave', 1, 0);

-- ------------------------------------------------------------
-- Permissions — Application Présence (1)
-- ------------------------------------------------------------
INSERT INTO permissions (id, application_id, name, code, description) VALUES
(1,  1, 'Voir les présences',      'presence.view',     'Consulter les présences du personnel'),
(2,  1, 'Enregistrer présences',   'presence.record',   'Enregistrer les présences'),
(3,  1, 'Modifier présences',      'presence.edit',     'Modifier les présences'),
(4,  1, 'Valider présences',       'presence.validate', 'Valider les présences'),
(5,  1, 'Voir le personnel',       'personnel.view',    'Consulter la liste du personnel'),
(6,  1, 'Gérer le personnel',      'personnel.manage',  'Créer, modifier, supprimer le personnel'),
(7,  1, 'Voir statistiques',       'stats.view',         'Consulter les statistiques et graphiques');

-- ------------------------------------------------------------
-- Permissions — Application Salaire (2)
-- ------------------------------------------------------------
INSERT INTO permissions (id, application_id, name, code, description) VALUES
(8,  2, 'Voir les salaires',     'salary.view',     'Consulter les bulletins et salaires'),
(9,  2, 'Élaborer les salaires', 'salary.manage',   'Créer et calculer les bulletins'),
(10, 2, 'Valider les salaires',  'salary.validate', 'Valider les bulletins de paie'),
(11, 2, 'Payer les salaires',    'salary.pay',      'Exécuter les paiements'),
(12, 2, 'Gérer les employés',    'employe.manage',  'Gérer les employés (CRUD)'),
(13, 2, 'Gérer les rubriques',   'rubrique.manage', 'Gérer les rubriques de paie'),
(14, 2, 'Exporter PDF',          'export.pdf',      'Exporter les bulletins en PDF');

-- ------------------------------------------------------------
-- Rôle Directeur
-- ------------------------------------------------------------
INSERT INTO role_permissions (role_id, permission_id) VALUES
(2, 1), (2, 4), (2, 5), (2, 7),
(2, 8), (2, 10), (2, 14);

-- ------------------------------------------------------------
-- Rôle Gestionnaire
-- ------------------------------------------------------------
INSERT INTO role_permissions (role_id, permission_id) VALUES
(3, 1), (3, 2), (3, 3), (3, 4), (3, 5), (3, 6), (3, 7),
(3, 8), (3, 9), (3, 10), (3, 12), (3, 13), (3, 14);

-- ------------------------------------------------------------
-- Rôle Chef de Service
-- ------------------------------------------------------------
INSERT INTO role_permissions (role_id, permission_id) VALUES
(4, 1), (4, 2), (4, 5), (4, 7),
(4, 8), (4, 9);

-- ------------------------------------------------------------
-- Rôle Agent
-- ------------------------------------------------------------
INSERT INTO role_permissions (role_id, permission_id) VALUES
(5, 1), (5, 8);

-- ------------------------------------------------------------
-- Rôle Auditeur
-- ------------------------------------------------------------
INSERT INTO role_permissions (role_id, permission_id) VALUES
(6, 1), (6, 5), (6, 8), (6, 18);

-- ------------------------------------------------------------
-- Rôles de l'administrateur sur les applications de démo
-- ------------------------------------------------------------
INSERT INTO user_roles (user_id, role_id, application_id) VALUES
(1, 1, 1),   -- admin sur Présence
(1, 1, 2);   -- admin sur Salaire
<?php
define('DB_NAME', getenv('WORDPRESS_DB_NAME') ?: 'wordpress');
define('DB_USER', getenv('WORDPRESS_DB_USER') ?: 'wordpress');
define('DB_PASSWORD', getenv('WORDPRESS_DB_PASSWORD') ?: 'wordpress-lab-only');
define('DB_HOST', getenv('WORDPRESS_DB_HOST') ?: 'db:3306');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');

define('AUTH_KEY',         'php2shell-stx-public-lab-auth-key');
define('SECURE_AUTH_KEY',  'php2shell-stx-public-lab-secure-auth-key');
define('LOGGED_IN_KEY',    'php2shell-stx-public-lab-logged-in-key');
define('NONCE_KEY',        'php2shell-stx-public-lab-nonce-key');
define('AUTH_SALT',        'php2shell-stx-public-lab-auth-salt');
define('SECURE_AUTH_SALT', 'php2shell-stx-public-lab-secure-auth-salt');
define('LOGGED_IN_SALT',   'php2shell-stx-public-lab-logged-in-salt');
define('NONCE_SALT',       'php2shell-stx-public-lab-nonce-salt');

$table_prefix = 'wpstx_';

define('WP_DEBUG', false);
define('WP_DEBUG_DISPLAY', false);
define('DISALLOW_FILE_EDIT', true);
define('AUTOMATIC_UPDATER_DISABLED', true);

if (!defined('ABSPATH')) {
    define('ABSPATH', __DIR__ . '/');
}
require_once ABSPATH . 'wp-settings.php';

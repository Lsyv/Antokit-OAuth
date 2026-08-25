<?php
declare(strict_types=1);

/** AuthHub 公共引导：配置、安全响应头、会话、数据库。 */

// ---------- 环境预检（避免裸 500） ----------
if (version_compare(PHP_VERSION, '8.1.0', '<')) {
    http_response_code(500);
    exit('AuthHub 需要 PHP >= 8.1，当前版本为 ' . PHP_VERSION
        . '。请升级 PHP 或切换 Apache 的 PHP 模块（如 libapache2-mod-php8.2）。');
}
if (!extension_loaded('pdo_mysql')) {
    http_response_code(500);
    exit('缺少 PHP 扩展 pdo_mysql。请安装并重启 Apache：<br>'
       . '<code>sudo apt install php-mysql &amp;&amp; sudo systemctl restart apache2</code>');
}

if (!file_exists(__DIR__ . '/config.php')) {
    http_response_code(503);
    exit('系统尚未安装，请先访问 install.php。');
}
$config = require __DIR__ . '/config.php';

header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline' https://js.hcaptcha.com https://newassets.hcaptcha.com; script-src 'self' https://js.hcaptcha.com https://*.hcaptcha.com; img-src 'self' data: https://ui-avatars.com https://*.hcaptcha.com; font-src 'self'; frame-src https://*.hcaptcha.com; connect-src 'self' https://*.hcaptcha.com; frame-ancestors 'none'; base-uri 'none'");

require_once __DIR__ . '/lib/db.php';
require_once __DIR__ . '/lib/security.php';
require_once __DIR__ . '/lib/mail.php';
require_once __DIR__ . '/lib/captcha.php';
require_once __DIR__ . '/lib/verify.php';

if (PHP_SAPI === 'cli') return;

$secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
       || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');

session_name($config['session']['name']);
// 持久化 Cookie：有效期 = 绝对会话时长（浏览器关闭不再丢失登录状态）
session_set_cookie_params([
    'lifetime' => $config['session']['absolute_time'],
    'path' => '/', 'domain' => '',
    'secure' => $secure, 'httponly' => true, 'samesite' => 'Lax',
]);
session_start();

db_init($config);
security_boot($config);
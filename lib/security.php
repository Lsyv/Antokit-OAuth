<?php
declare(strict_types=1);

/** 安全核心：CSRF、会话加固、限速、密码策略、输出转义。 */

function security_boot(array $config): void
{
    if (!isset($_SESSION['_fp'])) {
        $_SESSION['_fp'] = fingerprint($config);
        $_SESSION['_created'] = time();
        $_SESSION['_last'] = time();
    }
    if (!empty($_SESSION['_rotate'])) {
        session_regenerate_id(true);
        unset($_SESSION['_rotate']);
    }
    $s = $config['session'];
    if (time() - (int)$_SESSION['_last'] > $s['idle_timeout']
        || time() - (int)$_SESSION['_created'] > $s['absolute_time']) {
        session_unset(); session_destroy(); session_start();
        $_SESSION['expired'] = true;
    }
    $_SESSION['_last'] = time();
}

function fingerprint(array $config): string
{
    return hash_hmac('sha256', hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? ''), $config['app_key']);
}

function verify_fingerprint(array $config): bool
{
    return isset($_SESSION['_fp'])
        && hash_equals((string)$_SESSION['_fp'], fingerprint($config));
}

function csrf_token(): string
{
    if (empty($_SESSION['_csrf'])) $_SESSION['_csrf'] = bin2hex(random_bytes(32));
    return $_SESSION['_csrf'];
}

function csrf_field(): string
{
    return '<input type="hidden" name="_csrf" value="' . e(csrf_token()) . '">';
}

function csrf_verify(): void
{
    $sent = $_POST['_csrf'] ?? '';
    if (!is_string($sent) || empty($_SESSION['_csrf']) || !hash_equals($_SESSION['_csrf'], $sent)) {
        http_response_code(403);
        exit('无效的 CSRF 令牌，请刷新页面重试。');
    }
}

function require_login(): void
{
    // 指纹不匹配（UA 变化 / app_key 更换）或未登录时，彻底清掉旧会话，
    // 否则 login.php 会因残留的 uid 再次跳回，形成重定向死循环。
    if (empty($_SESSION['uid']) || !verify_fingerprint($GLOBALS['config'])) {
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $p = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'],
                (bool)$p['secure'], (bool)$p['httponly']);
        }
        session_destroy();
        // 记住回跳目标（含 OAuth authorize 请求）
        $target = $_SERVER['REQUEST_URI'] ?? 'dashboard.php';
        session_start();
        $_SESSION['return_to'] = $target;
        header('Location: login.php');
        exit;
    }
}

function current_user_id(): int { return (int)($_SESSION['uid'] ?? 0); }

function e(?string $v): string
{
    return htmlspecialchars($v ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function throttle_check(string $email): array
{
    $row = db_query('SELECT failed_attempts, last_failed_at FROM users WHERE email = ?', [$email])->fetch();
    if (!$row || (int)$row['failed_attempts'] < 5) return [true, 0];
    $elapsed = time() - (int)$row['last_failed_at'];
    if ($elapsed >= 900) return [true, 0];
    return [false, 900 - $elapsed];
}

function throttle_fail(string $email): void
{
    db_query('UPDATE users SET failed_attempts = failed_attempts + 1, last_failed_at = ? WHERE email = ?',
        [time(), $email]);
}

function throttle_reset(string $email): void
{
    db_query('UPDATE users SET failed_attempts = 0 WHERE email = ?', [$email]);
}

function validate_password(string $pwd): ?string
{
    if (strlen($pwd) < 8) return '密码至少需要 8 个字符。';
    if (!preg_match('/[A-Za-z]/', $pwd) || !preg_match('/\d/', $pwd)) {
        return '密码需同时包含字母和数字。';
    }
    return null;
}
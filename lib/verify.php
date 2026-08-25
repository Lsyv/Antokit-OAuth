<?php
declare(strict_types=1);

/**
 * 邮件验证令牌：邮箱验证 / 找回密码 / 管理员身份确认
 * 表 mail_tokens: token_hash, purpose, email, user_id, expires_at, used_at
 */

const MTTL = 1800; // 30 分钟

/** 创建令牌并返回明文（仅此一次可见） */
function mail_token_create(string $purpose, string $email, int $userId): string
{
    $token = bin2hex(random_bytes(24));
    db_query(
        'INSERT INTO mail_tokens (token_hash, purpose, email, user_id, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?)',
        [hash('sha256', $token), $purpose, strtolower($email), $userId, time() + MTTL, time()]
    );
    return $token;
}

/** 消费令牌 → [user_id, email] 或 null */
function mail_token_consume(string $purpose, string $token): ?array
{
    if (!preg_match('/^[a-f0-9]{48}$/', $token)) return null;
    $row = db_query(
        'SELECT * FROM mail_tokens WHERE token_hash = ? AND purpose = ? AND used_at IS NULL',
        [hash('sha256', $token), $purpose]
    )->fetch();
    if (!$row || (int)$row['expires_at'] < time()) return null;
    db_query('UPDATE mail_tokens SET used_at = ? WHERE id = ?', [time(), $row['id']]);
    return ['user_id' => (int)$row['user_id'], 'email' => $row['email']];
}

function site_base_url(array $config): string
{
    if (!empty($config['issuer'])) return rtrim($config['issuer'], '/');
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $dir  = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? '/'), '/');
    return $scheme . '://' . $host . $dir;
}
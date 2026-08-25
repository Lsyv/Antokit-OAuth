<?php
declare(strict_types=1);

/**
 * Personal Access Token（PAT，形如 sk-xxxxxxxx）
 * 用法：Authorization: Bearer sk-xxxx
 * 适用于脚本、CLI、服务器间直连等无法走 OAuth 浏览器流程的场景。
 * 权限 = 全量 scope（openid profile email），可随时吊销。
 */

function pat_create(int $userId, string $name): array
{
    $secret = 'sk-' . bin2hex(random_bytes(20)); // sk- + 40 hex
    db_query(
        'INSERT INTO api_tokens (token_hash, user_id, name, created_at) VALUES (?, ?, ?, ?)',
        [hash('sha256', $secret), $userId, trim(mb_substr($name, 0, 60)) ?: '未命名令牌', time()]
    );
    return ['token' => $secret, 'id' => (int)db()->lastInsertId()];
}

/** 校验 → [user 数组] 或 null；顺带记录最后使用时间（低频写入：每分钟最多一次由 DB 侧控制略过） */
function pat_authenticate(string $secret): ?array
{
    if (!preg_match('/^sk-[a-f0-9]{40}$/', $secret)) return null;
    $row = db_query(
        'SELECT t.id AS tid, t.last_used_at, u.* FROM api_tokens t
         JOIN users u ON u.id = t.user_id WHERE t.token_hash = ?',
        [hash('sha256', $secret)]
    )->fetch();
    if (!$row) return null;
    if ((int)$row['tid'] && time() - (int)$row['last_used_at'] > 60) {
        db_query('UPDATE api_tokens SET last_used_at = ? WHERE id = ?', [time(), $row['tid']]);
    }
    return [
        'id' => (int)$row['id'], 'name' => $row['name'], 'email' => $row['email'],
        'avatar' => $row['avatar'], 'updated_at' => $row['updated_at'],
    ];
}
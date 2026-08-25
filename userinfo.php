<?php
declare(strict_types=1);
/**
 * OIDC 风格用户信息端点 GET|POST /userinfo.php
 * 认证方式（按优先级）：
 *   1. Authorization: Bearer <access_token 或 sk-个人令牌>
 *   2. ?access_token=xxx（后备：Apache 未透传 Authorization 头的环境）
 */
require __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/lib/oauth_server.php';

function ui_fail(string $msg): never
{
    http_response_code(401);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    exit(json_encode(['error' => 'invalid_token', 'error_description' => $msg], JSON_UNESCAPED_UNICODE));
}

// ---------- 提取令牌 ----------
$header = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION']
        ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
$tokenValue = null;
if (preg_match('/^Bearer\s+(\S+)$/i', trim($header), $m)) {
    $tokenValue = $m[1];
} elseif (!empty($_REQUEST['access_token']) && is_string($_REQUEST['access_token'])) {
    $tokenValue = $_REQUEST['access_token']; // 后备通道
}
if (!$tokenValue) {
    header('WWW-Authenticate: Bearer realm="authhub"');
    ui_fail('缺少访问令牌');
}

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

// ---- Personal Access Token（sk- 开头）----
if (str_starts_with($tokenValue, 'sk-')) {
    require_once __DIR__ . '/lib/pat.php';
    $user = pat_authenticate($tokenValue);
    if (!$user) ui_fail('令牌无效或已被吊销');
    echo json_encode(user_payload($user, 'openid profile email'), JSON_UNESCAPED_UNICODE);
    exit;
}

// ---- OAuth access_token：优先验签（自包含），失败再查库（兼容旧令牌） ----
$payload = null;
if (str_contains($tokenValue, '.')) {
    $payload = token_verify_sig($config, $tokenValue);
}

if ($payload) {
    // 签名有效 → 直接取用户，无需查 tokens 表
    $u = db_query('SELECT * FROM users WHERE id = ?', [$payload['uid']])->fetch();
    if (!$u) ui_fail('用户不存在');
    $user = ['id'=>$u['id'],'name'=>$u['name'],'email'=>$u['email'],
             'avatar'=>$u['avatar'],'updated_at'=>$u['updated_at']];
    echo json_encode(user_payload($user, 'openid profile email'), JSON_UNESCAPED_UNICODE);
    exit;
}

// 旧格式令牌 / 兼容路径：查库
$hash = hash('sha256', $tokenValue);
$row = db_query(
    'SELECT t.expires_at, t.scope, u.* FROM tokens t JOIN users u ON u.id = t.user_id
     WHERE t.token_hash = ? AND t.type = "access"',
    [$hash]
)->fetch();

if (!$row) ui_fail('令牌无效');
if ((int)$row['expires_at'] < time()) ui_fail('令牌已过期');

$user = ['id'=>$row['id'],'name'=>$row['name'],'email'=>$row['email'],
         'avatar'=>$row['avatar'],'updated_at'=>$row['updated_at']];
echo json_encode(user_payload($user, (string)$row['scope']), JSON_UNESCAPED_UNICODE);
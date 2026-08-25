<?php
declare(strict_types=1);

/**
 * AuthHub — OAuth 2.0 授权服务器核心
 * 支持：authorization_code + refresh_token；客户端：web / native(app)
 * 遵循 RFC 6749 与 RFC 8252（Native App Best Practices）。
 */

const ACCESS_TOKEN_TTL  = 3600;      // access_token 有效期 1 小时
const REFRESH_TOKEN_TTL = 1209600;   // refresh_token 有效期 14 天
const AUTH_CODE_TTL     = 600;       // 授权码有效期 10 分钟

/** 已定义的 scope 及其用户可读描述 */
function oauth_scopes(): array
{
    return [
        'openid'    => ['身份标识', '获取您的用户 ID 和基础资料'],
        'profile'   => ['基本资料', '读取您的昵称与头像'],
        'email'     => ['邮箱地址', '读取您的注册邮箱'],
        'offline_access' => ['离线访问', '在您离线时刷新令牌（refresh_token）'],
    ];
}

function scope_descriptions(string $scope_str): array
{
    $known = oauth_scopes();
    $out = [];
    foreach (array_filter(explode(' ', $scope_str)) as $sc) {
        $out[$sc] = $known[$sc] ?? ['未识别权限', $sc];
    }
    return $out;
}

function valid_scope(string $scope_str): bool
{
    $valid = array_keys(oauth_scopes());
    foreach (array_filter(explode(' ', $scope_str)) as $sc) {
        if (!in_array($sc, $valid, true)) return false;
    }
    return true;
}

/** 查找应用：web 客户端按 client_id 匹配；native 按自定义 scheme 或 loopback IP 匹配 */
function app_find(string $client_id): ?array
{
    return db_query('SELECT * FROM apps WHERE client_id = ? AND status = "active"', [$client_id])->fetch() ?: null;
}

/** 校验 redirect_uri 是否已注册（精确匹配）。native 允许 loopback 任意端口（RFC 8252 §7.3） */
function redirect_uri_allowed(array $app, string $uri): bool
{
    foreach (array_filter(array_map('trim', explode("\n", (string)$app['redirect_uris']))) as $reg) {
        if ($app['type'] === 'native') {
            $rp = parse_url($reg); $ru = parse_url($uri);
            if (!$rp || !$ru) continue;
            // 自定义 scheme：完全匹配 scheme+host(path)；loopback: 仅 host 匹配，端口不限
            if (in_array($rp['host'] ?? '', ['127.0.0.1', '[::1]', 'localhost'], true)) {
                if (($rp['host'] ?? '') === ($ru['host'] ?? '')
                    && strtolower($rp['scheme'] ?? '') === strtolower($ru['scheme'] ?? '')) {
                    return true;
                }
            } elseif (($rp['scheme'] ?? '') === ($ru['scheme'] ?? '')
                   && ($rp['path'] ?? '') === ($ru['path'] ?? '')) {
                return true;
            }
        } elseif (hash_equals($reg, $uri)) {
            return true;
        }
    }
    return false;
}

/** 生成并存储授权码（一次性，10 分钟有效，绑定 client/redirect/scope/PKCE） */
function auth_code_create(int $uid, array $app, string $redirect, string $scope, ?string $pkce_challenge, ?string $pkce_method): string
{
    $code = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    db_query(
        'INSERT INTO auth_codes (code, user_id, app_id, redirect_uri, scope, pkce_challenge, pkce_method, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [$code, $uid, $app['id'], $redirect, $scope, $pkce_challenge, $pkce_method,
         time() + AUTH_CODE_TTL, time()]
    );
    return $code;
}

/** 消费授权码 → 返回记录或 null（一次性使用，重放即撤销该码签发的所有令牌） */
function auth_code_consume(string $code): ?array
{
    $row = db_query('SELECT * FROM auth_codes WHERE code = ?', [$code])->fetch();
    if (!$row) return null;
    db_query('DELETE FROM auth_codes WHERE code = ?', [$code]); // 无论成败都删除（一次性）
    if ((int)$row['expires_at'] < time()) return null;
    if (!empty($row['used'])) {
        // 检测到重放：撤销该用户此应用的全部令牌（RFC 6749 §4.1.2）
        db_query('DELETE FROM tokens WHERE user_id = ? AND app_id = ?', [(int)$row['user_id'], (int)$row['app_id']]);
        return null;
    }
    return $row;
}

/** 签发令牌对。access_token 为自包含签名格式：<payload_b64url>.<hmac>，无需查库即可验证 */
function token_sign(array $config, int $uid, int $expiresAt): string
{
    $payload = rtrim(strtr(base64_encode(json_encode(['uid' => $uid, 'exp' => $expiresAt])), '+/', '-_'), '=');
    $sig = hash_hmac('sha256', $payload, $config['app_key']);
    return $payload . '.' . $sig;
}

function token_verify_sig(array $config, string $token): ?array
{
    if (!preg_match('/^([A-Za-z0-9_-]+)\.([a-f0-9]{64})$/', $token, $m)) return null;
    if (!hash_equals(hash_hmac('sha256', $m[1], $config['app_key']), $m[2])) return null;
    $data = json_decode(base64_decode(strtr($m[1], '-_', '+/')), true);
    if (!$data || (int)$data['exp'] < time()) return null;
    return ['uid' => (int)$data['uid'], 'exp' => (int)$data['exp']];
}

/** 签发令牌对 */
function token_issue(int $uid, int $appId, string $scope, bool $withRefresh): array
{
    global $config;
    $access = token_sign($config, $uid, time() + ACCESS_TOKEN_TTL);
    db_query(
        'INSERT INTO tokens (token_hash, type, user_id, app_id, scope, expires_at, created_at)
         VALUES (?, "access", ?, ?, ?, ?, ?)',
        [hash('sha256', $access), $uid, $appId, $scope, time() + ACCESS_TOKEN_TTL, time()]
    );
    $out = [
        'access_token' => $access,
        'token_type' => 'Bearer',
        'expires_in' => ACCESS_TOKEN_TTL,
        'scope' => $scope,
    ];
    if ($withRefresh) {
        $refresh = 'rt_' . bin2hex(random_bytes(32));
        db_query(
            'INSERT INTO tokens (token_hash, type, user_id, app_id, scope, expires_at, created_at)
             VALUES (?, "refresh", ?, ?, ?, ?, ?)',
            [hash('sha256', $refresh), $uid, $appId, $scope, time() + REFRESH_TOKEN_TTL, time()]
        );
        $out['refresh_token'] = $refresh;
    }
    return $out;
}

/** 刷新令牌轮换：旧的立即失效 */
function token_refresh(string $refreshToken, int $appId): ?array
{
    $hash = hash('sha256', $refreshToken);
    $row = db_query('SELECT * FROM tokens WHERE token_hash = ? AND type = "refresh"', [$hash])->fetch();
    if (!$row || (int)$row['app_id'] !== $appId || (int)$row['expires_at'] < time()) return null;
    db_query('DELETE FROM tokens WHERE id = ?', [(int)$row['id']]);
    return token_issue((int)$row['user_id'], $appId, $row['scope'], true);
}

/** PKCE S256 校验 */
function pkce_verify(?string $challenge, ?string $method, string $verifier): bool
{
    if (!$challenge) return true; // 未启用 PKCE
    $method = $method ?: 'plain';
    $computed = $method === 'S256'
        ? rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=')
        : $verifier;
    return hash_equals($challenge, $computed);
}

/** OAuth 标准错误响应 */
function oauth_error(string $error, string $desc, ?string $redirect = null, ?string $state = null): never
{
    if ($redirect) {
        $q = http_build_query(array_filter(['error' => $error, 'error_description' => $desc, 'state' => $state]));
        header('Location: ' . $redirect . (str_contains($redirect, '?') ? '&' : '?') . $q);
        exit;
    }
    http_response_code(400);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode(['error' => $error, 'error_description' => $desc], JSON_UNESCAPED_UNICODE);
    exit;
}

/** 用户信息接口数据（供 userinfo.php 使用） */
function user_payload(array $user, string $scope): array
{
    $data = [];
    if (str_contains($scope, 'openid')) $data['sub'] = (string)$user['id'];
    if (str_contains($scope, 'profile')) {
        $data['name'] = $user['name'];
        $data['picture'] = $user['avatar'];
        $data['updated_at'] = (int)$user['updated_at'];
    }
    if (str_contains($scope, 'email')) {
        $data['email'] = $user['email'];
        $data['email_verified'] = true;
    }
    return $data;
}

/** Bearer 令牌校验 → 返回 [user, scope] 或 401 */
function bearer_authenticate(): array
{
    $header = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\s+(\S+)$/i', $header, $m)) {
        http_response_code(401);
        header('WWW-Authenticate: Bearer realm="authhub"');
        exit(json_encode(['error' => 'invalid_token'], JSON_UNESCAPED_UNICODE));
    }
    $row = db_query(
        'SELECT t.*, u.* FROM tokens t JOIN users u ON u.id = t.user_id
         WHERE t.token_hash = ? AND t.type = "access"',
        [hash('sha256', $m[1])]
    )->fetch();
    if (!$row || (int)$row['expires_at'] < time()) {
        http_response_code(401);
        exit(json_encode(['error' => 'invalid_token'], JSON_UNESCAPED_UNICODE));
    }
    return [['id'=>$row['id'],'name'=>$row['name'],'email'=>$row['email'],'avatar'=>$row['avatar'],
             'updated_at'=>$row['updated_at']], $row['scope']];
}
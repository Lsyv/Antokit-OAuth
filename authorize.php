<?php
declare(strict_types=1);
/**
 * OAuth 2.0 授权端点 GET /authorize.php
 * 参数：response_type=code & client_id & redirect_uri & scope & state & code_challenge(S256, native 必须)
 */
require __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/lib/oauth_server.php';
require_once __DIR__ . '/lib/view.php';

$req = $_GET;

$client_id    = (string)($req['client_id'] ?? '');
$redirect     = (string)($req['redirect_uri'] ?? '');
$responseType = (string)($req['response_type'] ?? '');
$scope        = trim((string)($req['scope'] ?? 'openid'));
$state        = (string)($req['state'] ?? '');
$pkceChallenge = isset($req['code_challenge']) ? (string)$req['code_challenge'] : null;
$pkceMethod    = isset($req['code_challenge_method']) ? (string)$req['code_challenge_method'] : null;
$nonce         = isset($req['nonce']) ? (string)$req['nonce'] : null;

// ---------- 客户端校验 ----------
$app = app_find($client_id);
if (!$app) {
    http_response_code(400);
    page_head('错误'); echo '<main class="card"><h1>无效的应用</h1><p class="sub">client_id 不存在或已被停用。</p></main>'; page_foot();
    exit;
}

// redirect_uri 必须先验证才能用于错误重定向（防开放重定向）
if (!$redirect || !redirect_uri_allowed($app, $redirect)) {
    http_response_code(400);
    page_head('错误');
    echo '<main class="card"><h1>重定向地址无效</h1><p class="sub">redirect_uri 未在应用中注册，已阻止跳转。</p></main>';
    page_foot(); exit;
}

// ---------- 标准参数校验（可安全重定向回客户端） ----------
if ($responseType !== 'code') {
    oauth_error('unsupported_response_type', '仅支持 response_type=code', $redirect, $state);
}
$scope = implode(' ', array_filter(explode(' ', $scope))); // 规范化
if (!valid_scope($scope)) {
    oauth_error('invalid_scope', '请求了未知的 scope', $redirect, $state);
}
// 原生 App 强制 PKCE（RFC 8252 最佳实践）
if ($app['type'] === 'native' && !$pkceChallenge) {
    oauth_error('invalid_request', '原生应用必须使用 PKCE (code_challenge)', $redirect, $state);
}
if ($pkceChallenge && !preg_match('/^[A-Za-z0-9\-_]{43,128}$/', $pkceChallenge)) {
    oauth_error('invalid_request', 'code_challenge 格式无效', $redirect, $state);
}
if ($pkceMethod && !in_array($pkceMethod, ['S256'], true)) {
    oauth_error('invalid_request', '仅支持 code_challenge_method=S256', $redirect, $state);
}

// ---------- 用户会话 ----------
if (empty($_SESSION['uid'])) {
    // 暂存授权请求，登录后回来继续
    $_SESSION['oauth_request'] = $_SERVER['QUERY_STRING'];
    $_SESSION['return_to'] = 'authorize.php?' . $_SERVER['QUERY_STRING'];
    header('Location: login.php');
    exit;
}

// 已登录：检查是否已有同 scope 授权记录 → 有则静默签发（免重复同意），无则渲染同意页
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'GET') {
    $existing = db_query(
        'SELECT scope FROM consents WHERE user_id = ? AND app_id = ?',
        [current_user_id(), $app['id']]
    )->fetch();
    if ($existing) {
        // 已授权 scope 是请求 scope 的超集 → 直接通过
        $granted = array_filter(explode(' ', (string)$existing['scope']));
        $need    = array_filter(explode(' ', $scope));
        if (!array_diff($need, $granted)) {
            $code = auth_code_create(current_user_id(), $app, $redirect, $scope, $pkceChallenge, $pkceMethod);
            $q = ['code' => $code];
            if ($state !== '') $q['state'] = $state;
            if ($nonce !== null) $q['nonce'] = $nonce;
            header('Location: ' . $redirect . (str_contains($redirect, '?') ? '&' : '?') . http_build_query($q));
            exit;
        }
    }
}

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    csrf_verify();

    if (($_POST['decision'] ?? '') !== 'allow') {
        oauth_error('access_denied', '用户拒绝了授权请求', $redirect, $state);
    }

    // 记录用户对应用的 scope 授权
    db_query(
        'INSERT INTO consents (user_id, app_id, scope, granted_at)
         VALUES (?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE scope = VALUES(scope), granted_at = VALUES(granted_at)',
        [current_user_id(), $app['id'], $scope, time()]
    );

    $code = auth_code_create(current_user_id(), $app, $redirect, $scope, $pkceChallenge, $pkceMethod);
    $q = ['code' => $code];
    if ($state !== '') $q['state'] = $state;
    if ($nonce !== null) $q['nonce'] = $nonce;
    header('Location: ' . $redirect . (str_contains($redirect, '?') ? '&' : '?') . http_build_query($q));
    exit;
}

// 已有完整授权 → 可选跳过同意页（同 scope 且未撤销）。此处仍显示以最大化透明度。
$user = db_query('SELECT * FROM users WHERE id = ?', [current_user_id()])->fetch();
$scopes = scope_descriptions($scope);

page_head('授权请求');
?>
<main class="card card-wide" role="main">
  <?= logo_html() ?>
  <h1>授权请求</h1>
  <div class="app-chip">
    <span class="app-avatar"><?= e(mb_strtoupper(mb_substr($app['name'], 0, 1))) ?></span>
    <div>
      <strong style="font-size:15px"><?= e($app['name']) ?></strong>
      <div class="hint">
        <?= $app['type'] === 'native' ? '应用（Native App）' : '网站（Web）' ?>
        · <span class="mono" style="font-size:11.5px"><?= e($client_id) ?></span>
      </div>
    </div>
  </div>

  <p class="sub" style="margin-bottom:12px">
    <strong style="color:var(--text)"><?= e($app['name']) ?></strong> 想要以
    <strong style="color:var(--text)"><?= e($user['email']) ?></strong> 的身份访问你的 AuthHub 账号：
  </p>

  <div class="scopes">
    <?php foreach ($scopes as $sc => [$t, $d]): ?>
    <div class="scope-item">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>
      <div><strong><?= e($t) ?></strong><span><?= e($d) ?> — <code class="inline"><?= e($sc) ?></code></span></div>
    </div>
    <?php endforeach; ?>
  </div>

  <?php if ($pkceChallenge): ?><p class="hint" style="margin-bottom:18px">🔒 此请求使用 PKCE 保护，授权码无法被截获使用。</p><?php endif; ?>

  <form method="post">
    <?= csrf_field() ?>
    <input type="hidden" name="decision" value="">
    <button type="submit" name="decision" value="deny" class="btn btn-ghost btn-block" style="margin-bottom:10px">拒绝</button>
    <button type="submit" name="decision" value="allow" class="btn btn-primary btn-block">允许访问</button>
  </form>
</main>
<?php page_foot();
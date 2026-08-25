<?php
require __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/lib/view.php';
require_once __DIR__ . '/lib/oauth_server.php';
require_once __DIR__ . '/lib/pat.php';
require_login();

$uid = current_user_id();
$user = db_query('SELECT * FROM users WHERE id = ?', [$uid])->fetch();

// ---------- 管理员验证 ----------
$isAdmin   = (int)($user['is_admin'] ?? 0) === 1;
$confirmed = (int)($user['admin_confirmed'] ?? 0) === 1;

if (($_POST['action'] ?? '') === 'send_admin_confirm') {
    csrf_verify();
    if (!$isAdmin) { http_response_code(403); exit('无权限'); }
    try {
        // 管理员验证：用自己的邮箱给自己发确认邮件
        $token = mail_token_create('admin_confirm', $user['email'], $uid);
        send_authhub_mail($config, $config['admin_email'], 'AuthHub 管理员身份确认',
            '你好 <b>' . e($user['name']) . '</b>，有人刚以管理员身份请求解锁 AuthHub 管理功能。<br>'
          . '如果是你本人操作，请点击下方按钮确认；否则请忽略并建议修改密码。链接 30 分钟内有效。',
            site_base_url($config) . '/verify_email.php?token=' . $token, '确认管理员身份');
        $_SESSION['flash_ok'] = '确认邮件已发送到 ' . $config['admin_email'] . '，请查收并点击链接完成验证（30 分钟内有效）。';
    } catch (Throwable $ex) {
        $_SESSION['flash_error'] = '邮件发送失败：' . $ex->getMessage();
    }
    header('Location: apps.php'); exit;
}

// ---------- 管理门禁：需要 is_admin + admin_confirmed ----------
if (!$isAdmin || !$confirmed) {
    page_head('开发者控制台', false);
    echo '<div class="shell"><div class="topbar">' . logo_html()
       . '<nav class="nav-links"><a href="dashboard.php">我的账号</a><a class="on" href="#">开发者控制台</a><a href="logout.php">退出登录</a></nav></div>';
    echo '<h1 class="page-title">🔒 需要管理员验证</h1><p class="sub" style="margin-bottom:24px">'
       . ($isAdmin
            ? '你的账号是管理员，但尚未通过邮箱身份确认。我们会向 <strong style="color:var(--text)">' 
              . e((string)$config['admin_email']) . '</strong> 发送一封确认邮件（发件人同为该邮箱），点击邮件中的链接即可解锁。'
            : '此页面仅对管理员开放。请使用安装时设置的管理员邮箱登录。')
       . '</p>';
    if ($okf = ($_SESSION['flash_ok'] ?? '')) { unset($_SESSION['flash_ok']);
        echo '<div class="alert alert-ok" role="status">' . e($okf) . '</div>'; }
    if ($erf = ($_SESSION['flash_error'] ?? '')) { unset($_SESSION['flash_error']);
        echo '<div class="alert alert-error" role="alert">' . e($erf) . '</div>'; }
    if ($isAdmin) {
        echo '<form method="post"><input type="hidden" name="_csrf" value="' . e(csrf_token())
           . '"><input type="hidden" name="action" value="send_admin_confirm">'
           . '<button type="submit" class="btn btn-primary btn-block">📧 发送管理员确认邮件</button></form>';
    } else {
        echo '<a class="btn btn-ghost btn-block" href="dashboard.php">返回我的账号</a>';
    }
    echo '</div>';
    page_foot(false);
    exit;
}

// ---------- 已验证管理员：应用管理 ----------
$error = '';
$apps = db_query('SELECT * FROM apps ORDER BY created_at DESC')->fetchAll(); // 管理员看全部

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_verify();
    $action = $_POST['action'] ?? '';

    if ($action === 'quick_create') {
        // 便捷创建：只需名称 + 回调地址，其他全自动
        $name  = trim((string)($_POST['name'] ?? ''));
        $uri   = strtolower(trim((string)($_POST['redirect_uri'] ?? '')));
        $type  = preg_match('#^(https?://(127\.0\.0\.1|localhost|\[::1\])|[a-z][a-z0-9+.-]*://)#', $uri)
               && !str_starts_with($uri, 'https://') ? 'native' : 'confidential';

        if ($name === '')                       $error = '请填写应用名称。';
        elseif (!filter_var($uri, FILTER_VALIDATE_URL) && !preg_match('#^[a-z][a-z0-9+.-]*://\S+$#', $uri))
                                                $error = '回调地址格式无效（示例：https://example.com/callback 或 myapp://callback）。';
        else {
            $clientId     = 'ah_' . bin2hex(random_bytes(12));
            $clientSecret = $type === 'confidential' ? 'ahs_' . bin2hex(random_bytes(24)) : '';
            db_query(
                'INSERT INTO apps (owner_id, client_id, client_secret_hash, name, type, redirect_uris, status, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, "active", ?)',
                [$uid, $clientId, $clientSecret ? hash('sha256', $clientSecret) : '',
                 $name, $type, $uri, time()]
            );
            $_SESSION['flash_newapp'] = [$clientId, $clientSecret];
            header('Location: apps.php'); exit;
        }
    }

    if (in_array($action, ['pat_create', 'pat_revoke'], true)) {
        if ($action === 'pat_create') {
            $name = trim((string)($_POST['token_name'] ?? ''));
            if ($name === '') $error = '请给令牌起个名字（例如：我的部署脚本）。';
            else {
                $pat = pat_create($uid, $name);
                $_SESSION['flash_pat'] = $pat['token'];
                header('Location: apps.php'); exit;
            }
        } else {
            db_query('DELETE FROM api_tokens WHERE id = ? AND user_id = ?',
                [(int)($_POST['token_id'] ?? 0), $uid]);
            $_SESSION['flash_ok'] = '令牌已吊销。';
            header('Location: apps.php'); exit;
        }
    }

    if (in_array($action, ['delete', 'rotate', 'toggle'], true)) {
        $appId = (int)($_POST['app_id'] ?? 0);
        $app = db_query('SELECT * FROM apps WHERE id = ?', [$appId])->fetch();
        if ($app) {
            if ($action === 'delete') {
                db_query('DELETE FROM apps WHERE id = ?', [$appId]);
                db_query('DELETE FROM tokens WHERE app_id = ?', [$appId]);
                db_query('DELETE FROM consents WHERE app_id = ?', [$appId]);
                $_SESSION['flash_ok'] = '「' . $app['name'] . '」已删除，相关令牌全部吊销。';
            } elseif ($action === 'rotate') {
                $newSecret = $app['type'] === 'confidential' ? 'ahs_' . bin2hex(random_bytes(24)) : '';
                db_query('UPDATE apps SET client_secret_hash = ? WHERE id = ?',
                    [$newSecret ? hash('sha256', $newSecret) : '', $appId]);
                db_query('DELETE FROM tokens WHERE app_id = ?', [$appId]);
                $_SESSION['flash_newapp'] = [(string)$app['client_id'], $newSecret];
            } else {
                $new = $app['status'] === 'active' ? 'suspended' : 'active';
                db_query('UPDATE apps SET status = ? WHERE id = ?', [$new, $appId]);
                if ($new === 'suspended') db_query('DELETE FROM tokens WHERE app_id = ?', [$appId]);
                $_SESSION['flash_ok'] = '已' . ($new === 'active' ? '启用' : '停用') . '「' . $app['name'] . '」。';
            }
            header('Location: apps.php'); exit;
        }
    }
}

$newApp = $_SESSION['flash_newapp'] ?? null; unset($_SESSION['flash_newapp']);
$flashPat = $_SESSION['flash_pat'] ?? ''; unset($_SESSION['flash_pat']);
$pats = db_query('SELECT id, name, created_at, last_used_at FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC', [$uid])->fetchAll();
$base   = site_base_url($config);
page_head('开发者控制台', false);
?>
<div class="shell">
  <div class="topbar">
    <?= logo_html() ?>
    <nav class="nav-links">
      <a href="dashboard.php">我的账号</a>
      <a class="on" href="apps.php">开发者控制台</a>
      <a href="logout.php">退出登录</a>
    </nav>
  </div>

<?php if ($flashPat): ?>
    <div class="alert alert-ok" role="status">
      ✅ 令牌已创建（<strong>仅显示这一次，请立即保存</strong>）：<br>
      <code class="inline" style="font-size:14px"><?= e($flashPat) ?></code><br>
      <span class="hint">用法：<code class="inline">curl -H "Authorization: Bearer <?= e($flashPat) ?>" <?= e($base) ?>/userinfo.php</code></span>
    </div>
  <?php endif; ?>
  <?php if ($newApp): ?>
    <div class="alert alert-ok" role="status">
      ✅ 凭据已生成（<strong>Secret 仅显示这一次</strong>）：<br>
      Client ID：<code class="inline" style="font-size:13.5px"><?= e($newApp[0]) ?></code>
      <?php if ($newApp[1]): ?><br>Client Secret：<code class="inline" style="font-size:13.5px"><?= e($newApp[1]) ?></code><?php endif; ?>
    </div>
  <?php endif; ?>
  <?php if ($okf = ($_SESSION['flash_ok'] ?? '')): unset($_SESSION['flash_ok']); ?>
    <div class="alert alert-ok" role="status"><?= e($okf) ?></div>
  <?php endif; ?>

  <h1 class="page-title">开发者控制台</h1>
  <p class="sub">👋 <?= e($user['name']) ?>，在这里为网站和 App 创建「使用 AuthHub 登录」。填两个框就行。</p>

  <!-- 便捷创建 -->
  <section style="margin-bottom:30px">
    <div class="panel" style="margin-bottom:22px">
      <div class="panel-head"><span class="panel-title">⚡ 快速创建应用</span>
        <span class="badge badge-info">只填 2 项 · 类型自动识别</span></div>
      <div class="panel-body">
        <?php if ($error): ?><div class="alert alert-error"><?= e($error) ?></div><?php endif; ?>
        <form method="post">
          <?= csrf_field() ?>
          <input type="hidden" name="action" value="quick_create">
          <div class="grid2">
            <div class="field">
              <label for="name">① 应用名称</label>
              <input id="name" name="name" required maxlength="60" placeholder="例如：我的博客">
            </div>
            <div class="field">
              <label for="redirect_uri">② 登录后跳转地址</label>
              <input id="redirect_uri" name="redirect_uri" required placeholder="https://example.com/callback">
            </div>
          </div>
          <p class="hint" style="margin:-4px 0 16px">
            💡 网站填 https:// 开头的完整地址；App 填自定义 scheme（如 <code class="inline">myapp://callback</code>）。
            https 地址自动按「Web 应用」处理（带 Secret），其余自动按「App」处理（PKCE 免密）。
          </p>
          <button type="submit" class="btn btn-primary">🚀 一键创建</button>
        </form>
      </div>
    </div>

    <!-- 应用列表 -->
    <div class="panel">
      <div class="panel-head"><span class="panel-title">📦 全部应用（<?= count($apps) ?>）</span></div>
      <?php if (!$apps): ?>
        <div class="panel-body" style="text-align:center;color:var(--text-2);padding:44px 22px">
          还没有应用。用上方表单 10 秒创建第一个。
        </div>
      <?php else: foreach ($apps as $a): ?>
        <div class="list-row" style="align-items:flex-start">
          <div style="min-width:0;flex:1">
            <strong style="font-size:15px"><?= e($a['name']) ?></strong>
            <span class="badge <?= $a['type']==='native'?'badge-warn':'badge-info' ?>" style="margin-left:8px"><?= $a['type']==='native'?'App':'Web' ?></span>
            <?php if ($a['status']!=='active'): ?><span class="badge badge-warn" style="margin-left:4px">已停用</span><?php endif; ?>
            <dl class="kv" style="margin-top:10px;font-size:13px">
              <dt>Client ID</dt><dd><code class="inline"><?= e($a['client_id']) ?></code></dd>
              <dt>回调地址</dt><dd><?= nl2br(e($a['redirect_uris'])) ?></dd>
              <dt>授权链接</dt><dd><code class="inline"><?= e($base) ?>/authorize.php?response_type=code&amp;client_id=<?= e($a['client_id']) ?>&amp;scope=openid profile email&amp;redirect_uri=…&amp;state=…</code></dd>
              <dt>令牌端点</dt><dd><code class="inline">POST <?= e($base) ?>/token.php</code></dd>
            </dl>
          </div>
          <div style="display:flex;flex-direction:column;gap:8px;flex-shrink:0">
            <form method="post">
              <?= csrf_field() ?><input type="hidden" name="action" value="toggle">
              <input type="hidden" name="app_id" value="<?= (int)$a['id'] ?>">
              <button class="btn btn-ghost btn-sm"><?= $a['status']==='active'?'⏸ 停用':'▶ 启用' ?></button>
            </form>
            <?php if ($a['type']==='confidential'): ?>
            <form method="post" onsubmit="return confirm('轮换后所有令牌失效，继续？')">
              <?= csrf_field() ?><input type="hidden" name="action" value="rotate">
              <input type="hidden" name="app_id" value="<?= (int)$a['id'] ?>">
              <button class="btn btn-ghost btn-sm">🔑 轮换密钥</button>
            </form>
            <?php endif; ?>
            <form method="post" onsubmit="return confirm('删除后所有用户授权和令牌都会吊销，确定？')">
              <?= csrf_field() ?><input type="hidden" name="action" value="delete">
              <input type="hidden" name="app_id" value="<?= (int)$a['id'] ?>">
              <button class="btn btn-danger btn-sm">删除</button>
            </form>
          </div>
        </div>
      <?php endforeach; endif; ?>
    </div>

    <!-- API 令牌 -->
    <div class="panel" style="margin-top:22px">
      <div class="panel-head">
        <span class="panel-title">🔑 API 访问令牌（Personal Access Token）</span>
        <span class="badge badge-info"><?= count($pats) ?> 个</span>
      </div>
      <div class="panel-body" style="border-bottom:1px solid var(--border)">
        <form method="post">
          <?= csrf_field() ?>
          <input type="hidden" name="action" value="pat_create">
          <label for="token_name" style="display:block;font-size:13px;color:var(--text-2);margin-bottom:7px">创建新令牌 —— 用于脚本 / CLI / 服务器间调用，无需走 OAuth 浏览器流程</label>
          <div style="display:flex;gap:10px;flex-wrap:wrap">
            <input id="token_name" name="token_name" required maxlength="60" placeholder="令牌名称，例如：我的部署脚本"
                   style="flex:1;min-width:220px;padding:11px 13px;font-size:14px;background:var(--bg-2);border:1px solid var(--border);border-radius:9px;color:var(--text);outline:none">
            <button type="submit" class="btn btn-primary btn-sm">生成 sk- 令牌</button>
          </div>
          <p class="hint" style="margin-top:8px">用法：<code class="inline">Authorization: Bearer sk-xxxx</code> 调用
            <code class="inline"><?= e($base) ?>/userinfo.php</code>。令牌仅显示一次；泄露请立即吊销。</p>
        </form>
      </div>
      <?php if (!$pats): ?>
        <div class="panel-body" style="text-align:center;color:var(--text-2);padding:32px 22px">
          还没有 API 令牌。
        </div>
      <?php else: foreach ($pats as $t): ?>
        <div class="list-row">
          <div style="min-width:0">
            <strong style="font-size:14.5px"><?= e($t['name']) ?></strong>
            <div class="hint">创建于 <?= date('Y-m-d H:i', (int)$t['created_at']) ?>
              · 最后使用：<?= $t['last_used_at'] ? date('Y-m-d H:i', (int)$t['last_used_at']) : '从未使用' ?></div>
          </div>
          <form method="post" onsubmit="return confirm('吊销后使用此令牌的脚本将立即失效，确定？')">
            <?= csrf_field() ?><input type="hidden" name="action" value="pat_revoke">
            <input type="hidden" name="token_id" value="<?= (int)$t['id'] ?>">
            <button class="btn btn-danger btn-sm">吊销</button>
          </form>
        </div>
      <?php endforeach; endif; ?>
    </div>
  </section>
</div>
<?php page_foot(false);
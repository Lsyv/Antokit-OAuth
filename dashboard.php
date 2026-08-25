<?php
require __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/lib/view.php';
require_once __DIR__ . '/lib/oauth_server.php';
require_login();

$uid = current_user_id();
$user = db_query('SELECT * FROM users WHERE id = ?', [$uid])->fetch();
if (!$user) { session_destroy(); header('Location: login.php'); exit; }

// ---------- 修改邮箱：向新邮箱发送验证邮件 ----------
if (($_POST['action'] ?? '') === 'change_email') {
    csrf_verify();
    $newEmail = strtolower(trim((string)($_POST['new_email'] ?? '')));
    if (!filter_var($newEmail, FILTER_VALIDATE_EMAIL)) {
        $_SESSION['flash_error'] = '新邮箱格式无效。';
    } elseif ($newEmail === $user['email']) {
        $_SESSION['flash_error'] = '新邮箱不能与当前邮箱相同。';
    } elseif (db_query('SELECT id FROM users WHERE email = ?', [$newEmail])->fetch()) {
        $_SESSION['flash_error'] = '该邮箱已被其他账号使用。';
    } elseif (!hcaptcha_verify($config, $capErr)) {
        $_SESSION['flash_error'] = $capErr;
    } else {
        try {
            // pending_email 先存起来，验证通过后才真正替换
            db_query('UPDATE users SET pending_email = ? WHERE id = ?', [$newEmail, $uid]);
            $token = mail_token_create('change_email', $newEmail, $uid);
            send_authhub_mail($config, $newEmail, '确认你的新 AuthHub 邮箱',
                '你好 <b>' . e($user['name']) . '</b>，有人请求将 AuthHub 账号邮箱变更为本地址。<br>'
              . '如果是你本人操作，请点击下方按钮完成变更；否则请忽略并建议修改密码。链接 30 分钟内有效。',
                site_base_url($config) . '/verify_email.php?token=' . $token, '确认变更邮箱');
            $_SESSION['flash_ok'] = '确认邮件已发送到 ' . $newEmail . '，请查收并点击链接完成变更（30 分钟内有效）。';
        } catch (Throwable $ex) {
            db_query('UPDATE users SET pending_email = NULL WHERE id = ?', [$uid]);
            $_SESSION['flash_error'] = '邮件发送失败：' . $ex->getMessage();
        }
    }
    header('Location: dashboard.php'); exit;
}

// ---------- 重新发送验证邮件 ----------
if (($_POST['action'] ?? '') === 'resend_verify') {
    csrf_verify();
    try {
        $token = mail_token_create('verify_email', $user['email'], $uid);
        send_authhub_mail($config, $user['email'], '验证你的 AuthHub 邮箱',
            '请点击下方按钮确认这是你的邮箱地址。',
            site_base_url($config) . '/verify_email.php?token=' . $token, '验证邮箱');
        $_SESSION['flash_ok'] = '验证邮件已重新发送到 ' . $user['email'] . '。';
    } catch (Throwable $ex) {
        $_SESSION['flash_error'] = '邮件发送失败：' . $ex->getMessage();
    }
    header('Location: dashboard.php'); exit;
}

// 撤销授权
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && ($_POST['action'] ?? '') === 'revoke') {
    csrf_verify();
    $appId = (int)($_POST['app_id'] ?? 0);
    db_query('DELETE FROM consents WHERE user_id = ? AND app_id = ?', [$uid, $appId]);
    db_query('DELETE FROM tokens WHERE user_id = ? AND app_id = ?', [$uid, $appId]);
    $_SESSION['flash_ok'] = '已撤销该应用的全部访问权限。';
    header('Location: dashboard.php'); exit;
}

$granted = db_query(
    'SELECT c.*, a.name AS app_name, a.type AS app_type, a.client_id
     FROM consents c JOIN apps a ON a.id = c.app_id
     WHERE c.user_id = ? ORDER BY c.granted_at DESC', [$uid])->fetchAll();

page_head('我的账号', false);
?>
<div class="shell">
  <div class="topbar">
    <?= logo_html() ?>
    <nav class="nav-links">
      <a class="on" href="dashboard.php">我的账号</a>
      <a href="logout.php">退出登录</a>
    </nav>
  </div>

  <?php if ($okf = ($_SESSION['flash_ok'] ?? '')): unset($_SESSION['flash_ok']); ?>
    <div class="alert alert-ok" role="status"><?= e($okf) ?></div>
  <?php endif; ?>
  <?php if ($erf = ($_SESSION['flash_error'] ?? '')): unset($_SESSION['flash_error']); ?>
    <div class="alert alert-error" role="alert"><?= e($erf) ?></div>
  <?php endif; ?>

  <h1 class="page-title">你好，<?= e($user['name']) ?> 👋</h1>
  <p class="sub" style="margin-bottom:26px"><?= e($user['email']) ?> · 注册于 <?= date('Y-m-d', (int)$user['created_at']) ?></p>

  <!-- 账号安全 -->
  <section style="margin-bottom:30px">
    <div class="panel">
      <div class="panel-head"><span class="panel-title">🛡️ 账号与邮箱</span>
        <?php if (!empty($user['email_verified'])): ?><span class="badge badge-ok">邮箱已验证</span>
        <?php else: ?><span class="badge badge-warn">邮箱未验证</span><?php endif; ?>
        <?php if ((int)$user['is_admin'] === 1): ?>
          <span class="badge badge-info">管理员<?= empty($user['admin_confirmed']) ? ' · 待确认' : ' · 已确认' ?></span>
        <?php endif; ?>
      </div>
      <div class="panel-body">
        <?php if (!empty($user['email_verified'])): ?>
          <!-- 修改邮箱 -->
          <form method="post">
            <?= csrf_field() ?>
            <input type="hidden" name="action" value="change_email">
            <label for="new_email" style="display:block;font-size:13px;color:var(--text-2);margin-bottom:7px">更换绑定邮箱（新邮箱将收到确认邮件）</label>
            <div style="display:flex;gap:10px;flex-wrap:wrap">
              <input type="email" id="new_email" name="new_email" required placeholder="new@example.com"
                     style="flex:1;min-width:220px;padding:11px 13px;font-size:14px;background:var(--bg-2);border:1px solid var(--border);border-radius:9px;color:var(--text);outline:none">
              <button type="submit" class="btn btn-primary btn-sm">发送确认邮件</button>
            </div>
          </form>
        <?php else: ?>
          <p style="font-size:14px;color:var(--text-2)">你的邮箱尚未验证。部分功能（如修改邮箱）需要验证后使用。</p>
          <form method="post" style="margin-top:12px">
            <?= csrf_field() ?>
            <input type="hidden" name="action" value="resend_verify">
            <button type="submit" class="btn btn-primary btn-sm">📧 重新发送验证邮件</button>
          </form>
        <?php endif; ?>
      </div>
    </div>
  </section>

  <section style="margin-bottom:34px">
    <div class="panel">
      <div class="panel-head">
        <span class="panel-title">🔐 已授权的应用与网站</span>
        <span class="badge badge-info"><?= count($granted) ?> 个</span>
      </div>
      <?php if (!$granted): ?>
        <div class="panel-body" style="text-align:center;color:var(--text-2);padding:44px 22px">
          还没有任何应用获得你的授权。<br>当你在第三方网站点击「使用 AuthHub 登录」时，授权会显示在这里。
        </div>
      <?php else: foreach ($granted as $g): ?>
        <div class="list-row">
          <div style="display:flex;align-items:center;gap:14px;min-width:0">
            <span class="app-avatar" style="width:40px;height:40px;font-size:16px;border-radius:11px"><?= e(mb_strtoupper(mb_substr($g['app_name'],0,1))) ?></span>
            <div style="min-width:0">
              <strong style="font-size:14.5px"><?= e($g['app_name']) ?></strong>
              <div class="hint"><?= e($g['client_id']) ?> · 授权于 <?= date('Y-m-d H:i', (int)$g['granted_at']) ?></div>
              <div class="hint" style="margin-top:3px"><?php
                foreach (array_keys(scope_descriptions((string)$g['scope'])) as $sc) {
                    echo '<span class="badge badge-ok" style="margin-right:5px">' . e($sc) . '</span>';
                } ?></div>
            </div>
          </div>
          <form method="post" onsubmit="return confirm('确定要撤销该应用的全部访问权限吗？')">
            <?= csrf_field() ?>
            <input type="hidden" name="action" value="revoke">
            <input type="hidden" name="app_id" value="<?= (int)$g['app_id'] ?>">
            <button class="btn btn-danger btn-sm" type="submit">撤销访问</button>
          </form>
        </div>
      <?php endforeach; endif; ?>
    </div>
  </section>

  <footer class="note" style="margin-top:8px">AuthHub · 统一身份认证平台</footer>
</div>
<?php page_foot(false);
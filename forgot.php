<?php
/** 找回密码：输入邮箱 → 发送重置链接（不泄露邮箱是否存在） */
require __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/lib/view.php';

$sent = false; $error = '';
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    csrf_verify();
    $email = strtolower(trim((string)($_POST['email'] ?? '')));
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = '请输入有效的邮箱地址。';
    } elseif (!hcaptcha_verify($config, $capErr)) {
        $error = $capErr;
    } else {
        $user = db_query('SELECT * FROM users WHERE email = ?', [$email])->fetch();
        if ($user) {
            try {
                $token = mail_token_create('reset_password', $email, (int)$user['id']);
                send_authhub_mail($config, $email, '重置你的 AuthHub 密码',
                    '我们收到了你（<b>' . e($user['name']) . '</b>）的重置密码请求。链接 30 分钟内有效。'
                  . '<br>如果不是本人操作，请忽略此邮件。',
                    site_base_url($config) . '/reset.php?token=' . $token, '重置密码');
            } catch (Throwable $ex) {
                error_log('[AuthHub] 重置邮件发送失败: ' . $ex->getMessage());
            }
        }
        $sent = true; // 无论是否存在都显示成功，防枚举
    }
}
page_head('找回密码');
?>
<main class="card" role="main">
  <?= logo_html() ?>
  <h1>找回密码</h1>
  <p class="sub">输入注册邮箱，我们会发送重置链接</p>

  <?php if ($sent): ?>
    <div class="alert alert-ok" role="status">
      ✅ 如果该邮箱已注册，重置链接已发出，请查收（30 分钟内有效）。
    </div>
    <a class="btn btn-ghost btn-block" href="login.php">返回登录</a>
  <?php else: ?>
    <?php if ($error): ?><div class="alert alert-error" role="alert"><?= e($error) ?></div><?php endif; ?>
    <form method="post" novalidate>
      <?= csrf_field() ?>
      <div class="field">
        <label for="email">电子邮箱</label>
        <input type="email" id="email" name="email" required autofocus value="<?= e($_POST['email'] ?? '') ?>">
      </div>
      <?php if ($w = hcaptcha_widget($config)): ?><?= $w ?><?php endif; ?>
      <button type="submit" class="btn btn-primary btn-block" style="margin-top:8px">发送重置链接</button>
    </form>
    <p style="margin-top:20px;text-align:center;font-size:14px;color:var(--text-2)">
      <a href="login.php" style="color:var(--accent);font-weight:600;text-decoration:none">← 返回登录</a>
    </p>
  <?php endif; ?>
</main>
<?php page_foot();
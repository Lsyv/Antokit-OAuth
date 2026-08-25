<?php
require __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/lib/view.php';

if (!empty($_SESSION['uid'])) { header('Location: dashboard.php'); exit; }

$error = '';
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    csrf_verify();
    $name  = trim((string)($_POST['name'] ?? ''));
    $email = strtolower(trim((string)($_POST['email'] ?? '')));
    $pwd   = (string)($_POST['password'] ?? '');
    $pwd2  = (string)($_POST['password2'] ?? '');

    if ($name === '' || mb_strlen($name) > 60)          $error = '请输入姓名（不超过 60 字）。';
    elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) $error = '请输入有效的邮箱地址。';
    elseif ($err = validate_password($pwd))              $error = $err;
    elseif ($pwd !== $pwd2)                              $error = '两次输入的密码不一致。';
    elseif (!hcaptcha_verify($config, $capErr))          $error = $capErr;
    else {
        if (db_query('SELECT id FROM users WHERE email = ?', [$email])->fetch()) {
            $error = '该邮箱已被注册。';
        } else {
            db_query(
                'INSERT INTO users (email, name, password_hash, created_at) VALUES (?, ?, ?, ?)',
                [$email, $name, password_hash($pwd, PASSWORD_ARGON2ID), time()]
            );
            // 发送邮箱验证邮件（失败不阻断注册）
            try {
                $uid = (int)db()->lastInsertId();
                $token = mail_token_create('verify_email', $email, $uid);
                send_authhub_mail($config, $email, '验证你的 AuthHub 邮箱',
                    '你好 <b>' . e($name) . '</b>，感谢注册 AuthHub！请点击下方按钮确认这是你的邮箱地址。',
                    site_base_url($config) . '/verify_email.php?token=' . $token, '验证邮箱');
            } catch (Throwable $ex) {
                error_log('[AuthHub] 注册验证邮件发送失败: ' . $ex->getMessage());
            }
            session_regenerate_id(true);
            $_SESSION['flash_ok'] = '注册成功！我们已向 ' . $email . ' 发送了验证邮件，请查收后登录。';
            header('Location: login.php');
            exit;
        }
    }
}
page_head('注册');
?>
<main class="card" role="main">
  <?= logo_html() ?>
  <h1>创建账号</h1>
  <p class="sub">一个账号，登录所有接入 AuthHub 的网站和应用</p>

  <?php if ($error): ?><div class="alert alert-error" role="alert"><?= e($error) ?></div><?php endif; ?>

  <form method="post" novalidate>
    <?= csrf_field() ?>
    <div class="field">
      <label for="name">姓名</label>
      <input type="text" id="name" name="name" autocomplete="name" required maxlength="60"
             value="<?= e($_POST['name'] ?? '') ?>">
    </div>
    <div class="field">
      <label for="email">电子邮箱</label>
      <input type="email" id="email" name="email" autocomplete="username" required
             value="<?= e($_POST['email'] ?? '') ?>">
    </div>
    <div class="grid2">
      <div class="field">
        <label for="password">密码</label>
        <input type="password" id="password" name="password" autocomplete="new-password" required minlength="8">
      </div>
      <div class="field">
        <label for="password2">确认密码</label>
        <input type="password" id="password2" name="password2" autocomplete="new-password" required>
      </div>
    </div>
    <p class="hint" style="margin:-6px 0 14px">至少 8 位，需同时包含字母和数字。</p>
    <?php if ($w = hcaptcha_widget($config)): ?>
      <div style="margin-bottom:18px"><?= $w ?></div>
    <?php endif; ?>
    <button type="submit" class="btn btn-primary btn-block">创建账号</button>
  </form>

  <p style="margin-top:24px;text-align:center;font-size:14px;color:var(--text-2)">
    已有账号？<a href="login.php" style="color:var(--accent);font-weight:600;text-decoration:none">去登录</a>
  </p>
</main>
<?php page_foot();
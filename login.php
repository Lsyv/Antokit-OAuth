<?php
require __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/lib/view.php';

if (!empty($_SESSION['uid'])) { header('Location: dashboard.php'); exit; }

$error = '';
$ok    = $_SESSION['flash_ok'] ?? '';
unset($_SESSION['flash_ok']);
$returnTo = $_SESSION['return_to'] ?? '';

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    csrf_verify();
    $email = trim((string)($_POST['email'] ?? ''));
    $pwd   = (string)($_POST['password'] ?? '');

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = '请输入有效的邮箱地址。';
    } elseif (!hcaptcha_verify($config, $capErr)) {
        $error = $capErr;
    } else {
        [$allowed, $wait] = throttle_check($email);
        if (!$allowed) {
            $error = "尝试次数过多，请在 {$wait} 秒后重试。";
        } else {
            $user = db_query('SELECT * FROM users WHERE email = ?', [$email])->fetch();
            if ($user && $user['password_hash'] && password_verify($pwd, $user['password_hash'])) {
                if (password_needs_rehash($user['password_hash'], PASSWORD_ARGON2ID)) {
                    db_query('UPDATE users SET password_hash = ? WHERE id = ?',
                        [password_hash($pwd, PASSWORD_ARGON2ID), $user['id']]);
                }
                session_regenerate_id(true);
                throttle_reset($email);
                $_SESSION['uid'] = (int)$user['id'];
                $_SESSION['uname'] = $user['name'];
                $to = $_SESSION['return_to'] ?? 'dashboard.php';
                unset($_SESSION['return_to']);
                header('Location: ' . $to);
                exit;
            }
            throttle_fail($email);
            $error = '邮箱或密码不正确。';
        }
    }
}
page_head('登录');
?>
<main class="card" role="main">
  <?= logo_html() ?>
  <h1>欢迎回来</h1>
  <p class="sub">登录你的 AuthHub 账号以继续</p>

  <?php if ($error): ?><div class="alert alert-error" role="alert"><?= e($error) ?></div><?php endif; ?>
  <?php if ($ok): ?><div class="alert alert-ok" role="status"><?= e($ok) ?></div><?php endif; ?>
  <?php if (!empty($_SESSION['expired'])): unset($_SESSION['expired']); ?>
    <div class="alert alert-info" role="alert">会话已过期，请重新登录。</div>
  <?php endif; ?>

  <form method="post" novalidate>
    <?= csrf_field() ?>
    <div class="field">
      <label for="email">电子邮箱</label>
      <input type="email" id="email" name="email" autocomplete="username" required autofocus
             value="<?= e($_POST['email'] ?? '') ?>">
    </div>
    <div class="field">
      <label for="password">密码</label>
      <input type="password" id="password" name="password" autocomplete="current-password" required>
    </div>
    <?php if ($w = hcaptcha_widget($config)): ?><?= $w ?><?php endif; ?>
    <button type="submit" class="btn btn-primary btn-block" style="margin-top:8px">登 录</button>
  </form>

  <p style="margin-top:16px;text-align:center;font-size:13.5px">
    <a href="forgot.php" style="color:var(--text-2);text-decoration:none">忘记密码？</a>
  </p>

  <p style="margin-top:24px;text-align:center;font-size:14px;color:var(--text-2)">
    还没有账号？<a class="link" href="register.php<?= $returnTo ? '' : '' ?>" style="color:var(--accent);font-weight:600;text-decoration:none">立即注册</a>
  </p>
</main>
<?php page_foot();
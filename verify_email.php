<?php
/** 邮箱验证：处理 verify_email 与 admin_confirm 两类令牌 */
require __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/lib/view.php';

$token = (string)($_GET['token'] ?? '');
$purpose = '';
$ok = false;

// 管理员确认令牌带 purpose 前缀：admin_confirm:<uid>
if (preg_match('/^([a-z_]+):/', $token, $m)) {
    $purpose = $m[1];
}

$data = null;
foreach (['verify_email', 'admin_confirm', 'change_email'] as $p) {
    if ($data = mail_token_consume($p, $token)) { $purpose = $p; break; }
}

if ($data) {
    if ($purpose === 'verify_email') {
        db_query('UPDATE users SET email_verified = 1 WHERE id = ?', [$data['user_id']]);
        $msg = '邮箱验证成功！你现在可以使用全部功能了。';
    } elseif ($purpose === 'change_email') {
        // 变更邮箱：将 pending_email 替换为正式邮箱
        $u = db_query('SELECT * FROM users WHERE id = ? AND pending_email = ?',
            [$data['user_id'], $data['email']])->fetch();
        if (!$u) {
            $msg = '变更请求不存在或已被处理。';
            $ok = false;
        } else {
            db_query('UPDATE users SET email = ?, pending_email = NULL, email_verified = 1 WHERE id = ?',
                [$data['email'], $u['id']]);
            db_query('DELETE FROM mail_tokens WHERE purpose = "admin_confirm" AND user_id = ?', [$u['id']]);
            $msg = '邮箱已变更为 ' . $data['email'] . '，请今后使用新邮箱登录。';
        }
    } else {
        // 管理员身份确认：必须是 config 中的管理员邮箱对应的用户
        $u = db_query('SELECT * FROM users WHERE id = ? AND email = ?',
            [$data['user_id'], strtolower((string)($config['admin_email'] ?? ''))])->fetch();
        if ($u && (int)$u['is_admin'] === 1) {
            db_query('UPDATE users SET admin_confirmed = 1 WHERE id = ?', [$u['id']]);
            $msg = '管理员身份确认成功！开发者控制台等管理功能已解锁。';
        } else {
            $msg = '该链接与管理员账号不匹配。';
            $ok = false;
        }
    }
    $ok = $ok || true;
} else {
    $msg = '链接无效或已过期。';
    $ok = false;
}

page_head($purpose === 'admin_confirm' ? '管理员确认' : '邮箱验证');
?>
<main class="card" style="text-align:center" role="main">
  <?= logo_html() ?>
  <h1><?= $ok ? '✅' : '⚠️' ?></h1>
  <p class="sub" style="margin-bottom:26px;font-size:15px"><?= e($msg) ?></p>
  <a class="btn btn-primary btn-block" href="dashboard.php">前往我的账号</a>
  <a class="btn btn-ghost btn-block" href="login.php" style="margin-top:10px">返回登录</a>
</main>
<?php page_foot();
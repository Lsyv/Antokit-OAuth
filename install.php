<?php
/**
 * AuthHub 安装向导 v3
 * 数据库 → 管理员账号（邮箱即管理员邮箱）→ SMTP → hCaptcha
 * ⚠ 安装完成后请立即删除本文件。
 */
declare(strict_types=1);
session_start();
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');

$error = ''; $done = false; $log = []; $adminEmail = '';
$checks = [
    [version_compare(PHP_VERSION, '8.1.0', '>='), 'PHP >= 8.1', PHP_VERSION],
    [extension_loaded('pdo_mysql'), 'PDO MySQL 扩展', ''],
    [extension_loaded('openssl'), 'OpenSSL（SMTP SSL/TLS）', ''],
    [function_exists('curl_init'), 'cURL（hCaptcha 校验）', ''],
    [is_writable(__DIR__), '目录可写', ''],
];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (empty($_SESSION['icsrf']) || !hash_equals($_SESSION['icsrf'], $_POST['_csrf'] ?? '')) {
        $error = 'CSRF 校验失败，请刷新页面。';
    } else {
        try {
            $host = trim($_POST['host'] ?: '127.0.0.1');
            $port = (int)($_POST['port'] ?: 3306);
            $name = preg_replace('/[^a-z0-9_]/i', '', $_POST['dbname']) ?: 'authhub';
            $user = $_POST['dbuser']; $pass = $_POST['dbpass'];

            // ---- 管理员 ----
            $adminEmail = strtolower(trim($_POST['admin_email'] ?? ''));
            $adminPass  = (string)($_POST['admin_pass'] ?? '');
            if (!filter_var($adminEmail, FILTER_VALIDATE_EMAIL)) throw new RuntimeException('管理员邮箱格式无效');
            if (strlen($adminPass) < 8) throw new RuntimeException('管理员密码至少 8 位');

            // ---- SMTP ----
            $smtpHost = trim($_POST['smtp_host'] ?? '');
            $smtpUser = trim($_POST['smtp_user'] ?: $adminEmail);   // 默认与管理员邮箱一致
            $smtpFrom = trim($_POST['smtp_from'] ?: $smtpUser);

            // ---- 建库建表 ----
            $pdo = new PDO("mysql:host=$host;port=$port;charset=utf8mb4", $user, $pass, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]);
            $pdo->exec("CREATE DATABASE IF NOT EXISTS `$name` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
            $pdo->exec("USE `$name`");

            foreach ([
'CREATE TABLE IF NOT EXISTS users (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(190) NOT NULL UNIQUE,
  name VARCHAR(120) NOT NULL DEFAULT "",
  password_hash VARCHAR(255) NULL,
  is_admin TINYINT UNSIGNED NOT NULL DEFAULT 0,
  role ENUM("user","admin") NOT NULL DEFAULT "user",
  admin_confirmed TINYINT UNSIGNED NOT NULL DEFAULT 0,
  email_verified TINYINT UNSIGNED NOT NULL DEFAULT 0,
  pending_email VARCHAR(190) NULL,
  failed_attempts INT UNSIGNED NOT NULL DEFAULT 0,
  last_failed_at BIGINT UNSIGNED NOT NULL DEFAULT 0,
  avatar VARCHAR(512) NULL,
  created_at BIGINT UNSIGNED NOT NULL,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4',
'CREATE TABLE IF NOT EXISTS apps (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  owner_id BIGINT UNSIGNED NOT NULL,
  client_id VARCHAR(64) NOT NULL UNIQUE,
  client_secret_hash CHAR(64) NOT NULL DEFAULT "",
  name VARCHAR(120) NOT NULL,
  type ENUM("confidential","native") NOT NULL DEFAULT "confidential",
  redirect_uris TEXT NOT NULL,
  status ENUM("active","suspended") NOT NULL DEFAULT "active",
  created_at BIGINT UNSIGNED NOT NULL,
  INDEX idx_owner (owner_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4',
'CREATE TABLE IF NOT EXISTS auth_codes (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  code CHAR(43) NOT NULL UNIQUE,
  user_id BIGINT UNSIGNED NOT NULL,
  app_id INT UNSIGNED NOT NULL,
  redirect_uri VARCHAR(512) NOT NULL,
  scope VARCHAR(255) NOT NULL,
  pkce_challenge VARCHAR(128) NULL,
  pkce_method VARCHAR(10) NULL,
  expires_at BIGINT UNSIGNED NOT NULL,
  created_at BIGINT UNSIGNED NOT NULL,
  INDEX idx_code (code), INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4',
'CREATE TABLE IF NOT EXISTS tokens (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  token_hash CHAR(64) NOT NULL,
  type ENUM("access","refresh") NOT NULL,
  user_id BIGINT UNSIGNED NOT NULL,
  app_id INT UNSIGNED NOT NULL,
  scope VARCHAR(255) NOT NULL,
  expires_at BIGINT UNSIGNED NOT NULL,
  created_at BIGINT UNSIGNED NOT NULL,
  INDEX idx_token (token_hash), INDEX idx_app_user (app_id, user_id), INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4',
'CREATE TABLE IF NOT EXISTS consents (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  app_id INT UNSIGNED NOT NULL,
  scope VARCHAR(255) NOT NULL,
  granted_at BIGINT UNSIGNED NOT NULL,
  UNIQUE KEY uk_user_app (user_id, app_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4',
'CREATE TABLE IF NOT EXISTS mail_tokens (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  token_hash CHAR(64) NOT NULL,
  purpose VARCHAR(32) NOT NULL,
  email VARCHAR(190) NOT NULL,
  user_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
  expires_at BIGINT UNSIGNED NOT NULL,
  created_at BIGINT UNSIGNED NOT NULL,
  used_at BIGINT UNSIGNED NULL,
  INDEX idx_token (token_hash), INDEX idx_purpose_email (purpose, email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4',
'CREATE TABLE IF NOT EXISTS api_tokens (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  token_hash CHAR(64) NOT NULL UNIQUE,
  user_id BIGINT UNSIGNED NOT NULL,
  name VARCHAR(60) NOT NULL DEFAULT "",
  created_at BIGINT UNSIGNED NOT NULL,
  last_used_at BIGINT UNSIGNED NOT NULL DEFAULT 0,
  INDEX idx_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4',
                        ] as $sql) {
                $pdo->exec($sql);
            }
            $log[] = "数据库 `$name` 与 7 张表已就绪";

            // ---- 管理员账号（role=admin）----
            $q = $pdo->prepare('SELECT id FROM users WHERE email = ?');
            $q->execute([$adminEmail]);
            if ($row = $q->fetch()) {
                $pdo->prepare('UPDATE users SET password_hash=?, role="admin", is_admin=1 WHERE id=?')
                    ->execute([password_hash($adminPass, PASSWORD_ARGON2ID), $row['id']]);
                $log[] = '已重置现有账号为管理员';
            } else {
                $pdo->prepare('INSERT INTO users (email,name,password_hash,is_admin,role,email_verified,created_at) VALUES (?, "Administrator", ?, 1, "admin", 0, ?)')
                    ->execute([$adminEmail, password_hash($adminPass, PASSWORD_ARGON2ID), time()]);
                $log[] = '管理员账号已创建';
            }

            // ---- config.php ----
            $cfg = [
                'db' => ['host'=>$host,'port'=>$port,'name'=>$name,'user'=>$user,'pass'=>$pass,'charset'=>'utf8mb4'],
                'app_key' => bin2hex(random_bytes(32)),
                'session' => ['name'=>'AUTHHUBSESS','idle_timeout'=>1800,'absolute_time'=>43200],
                'issuer' => trim($_POST['site_url'] ?? ''),
                'admin_email' => $adminEmail,
                'smtp' => [
                    'host'  => $smtpHost,
                    'port'  => (int)($_POST['smtp_port'] ?: ($smtpHost ? 587 : 25)),
                    'secure'=> in_array($_POST['smtp_secure'] ?? '', ['ssl','tls','none']) ? $_POST['smtp_secure'] : 'tls',
                    'user'  => $smtpUser,
                    'pass'  => (string)($_POST['smtp_pass'] ?? ''),
                    'from_email' => $smtpFrom,
                    'from_name'  => trim($_POST['smtp_from_name'] ?: 'AuthHub'),
                ],
                'hcaptcha' => [
                    'enabled' => trim((string)($_POST['hcaptcha_sitekey'] ?? '')) !== '',
                    'sitekey' => trim((string)($_POST['hcaptcha_sitekey'] ?? '')),
                    'secret'  => trim((string)($_POST['hcaptcha_secret'] ?? '')),
                ],
            ];
            file_put_contents(__DIR__ . '/config.php',
                "<?php\n/** AuthHub 配置 —— 由 install.php 于 " . date('c') . " 生成 */\nreturn "
                . var_export($cfg, true) . ";\n", LOCK_EX);
            chmod(__DIR__ . '/config.php', 0640);
            $log[] = 'config.php 已生成';
            $done = true;
        } catch (Throwable $ex) {
            $error = $ex->getMessage();
        }
    }
}
if (empty($_SESSION['icsrf'])) $_SESSION['icsrf'] = bin2hex(random_bytes(16));
function iv(string $k, string $d = ''): string { return htmlspecialchars($_POST[$k] ?? $d); }
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>AuthHub 安装向导</title>
<style>
:root{--b:#0a0b10;--s:rgba(255,255,255,.05);--bd:rgba(255,255,255,.09);--t:#f4f5f7;--t2:#9aa0ae;--ac:#6366f1;--r:14px;--rs:9px}
*{box-sizing:border-box;margin:0}html{color-scheme:dark}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC',sans-serif;background:var(--b);color:var(--t);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:28px 18px;line-height:1.55}
body::before{content:'';position:fixed;inset:0;background:radial-gradient(600px 400px at 15% 10%,rgba(99,102,241,.16),transparent 65%),radial-gradient(500px 380px at 85% 85%,rgba(34,211,238,.1),transparent 65%);pointer-events:none}
.card{position:relative;width:100%;max-width:620px;background:var(--s);border:1px solid var(--bd);border-radius:var(--r);padding:38px 34px;backdrop-filter:blur(24px);animation:rise .5s cubic-bezier(.2,.8,.25,1)}
@keyframes rise{from{opacity:0;transform:translateY(14px)}}
.logo{display:inline-flex;align-items:center;gap:11px;text-decoration:none;color:var(--t);margin-bottom:6px}
.logo-mark{width:34px;height:34px;border-radius:10px;background:linear-gradient(135deg,#6366f1,#22d3ee);display:grid;place-items:center;font-weight:800;color:#fff}
.logo-name{font-size:19px;font-weight:700}
h1{font-size:25px;font-weight:700;margin:16px 0 4px;letter-spacing:-.02em}
.sub{color:var(--t2);font-size:14px;margin-bottom:26px}
.sec{margin-top:26px;padding-top:22px;border-top:1px solid var(--bd)}
.sec-title{font-size:13px;font-weight:650;color:#a5b4fc;text-transform:uppercase;letter-spacing:.08em;margin-bottom:14px}
.field{margin-bottom:15px}
.field label{display:block;font-size:12.5px;font-weight:550;color:var(--t2);margin-bottom:6px}
input,select{width:100%;padding:11px 13px;font-size:14px;background:rgba(0,0,0,.25);border:1px solid var(--bd);border-radius:var(--rs);color:var(--t);outline:none;transition:.18s;font-family:inherit}
input:focus,select:focus{border-color:var(--ac);box-shadow:0 0 0 3px rgba(99,102,241,.22)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}.grid3{display:grid;grid-template-columns:110px 110px 1fr;gap:12px}
@media(max-width:560px){.grid2,.grid3{grid-template-columns:1fr}}
.hint{font-size:12px;color:#5d6472;margin-top:5px;line-height:1.5}
.btn{width:100%;padding:13px;font-size:15px;font-weight:600;border:none;border-radius:var(--rs);background:var(--ac);color:#fff;cursor:pointer;margin-top:10px;transition:.18s;font-family:inherit}
.btn:hover{background:#7679f3;box-shadow:0 6px 24px rgba(99,102,241,.45)}
.alert{border-radius:var(--rs);padding:12px 15px;font-size:13.5px;margin-bottom:18px;border:1px solid}
.alert-error{background:rgba(248,113,113,.09);border-color:rgba(248,113,113,.25);color:#fca5a5}
.alert-ok{background:rgba(52,211,153,.09);border-color:rgba(52,211,153,.25);color:#6ee7b7}
.ok{color:#34d399}.bad{color:#f87171}
code{font-family:ui-monospace,monospace;font-size:12px;background:rgba(0,0,0,.3);padding:1px 6px;border-radius:5px;color:#67e8f9}
</style>
</head>
<body>
<main class="card">
  <span class="logo"><span class="logo-mark">A</span><span class="logo-name">AuthHub</span></span>
  <h1>安装向导</h1>
  <p class="sub">部署你的 OAuth 2.0 统一身份认证平台 · 共 4 步配置</p>

<?php foreach ($checks as [$ok, $label, $detail]): ?>
  <p style="font-size:13.5px;margin:4px 0">
    <span class="<?= $ok ? 'ok' : 'bad' ?>"><?= $ok ? '✔' : '✘' ?></span> <?= htmlspecialchars($label) ?>
    <?php if ($detail): ?><span style="color:var(--t2)"> — <?= htmlspecialchars($detail) ?></span><?php endif; ?>
  </p>
<?php endforeach; ?>

<?php if ($error): ?><div class="alert alert-error"><?= htmlspecialchars($error) ?></div><?php endif; ?>

<?php if ($done): ?>
  <div class="alert alert-ok">🎉 安装完成！</div>
  <?php foreach ($log as $l): ?><p class="hint"><?= htmlspecialchars($l) ?></p><?php endforeach; ?>
  <p class="hint" style="margin-top:12px">
    首次登录后系统会向你设置的管理员邮箱 <code><?= htmlspecialchars($adminEmail) ?></code> 发送<b>管理员身份确认邮件</b>（发件人也是这个邮箱），
    点击邮件中的链接完成确认即可使用开发者控制台等管理功能。
  </p>
  <a href="login.php" class="btn" style="text-decoration:none;text-align:center;display:block">前往登录页 →</a>
  <p class="hint" style="margin-top:14px;color:#fbbf24">⚠ 请立即删除本文件（install.php）！</p>
<?php else: ?>
  <form method="post" autocomplete="off">
    <input type="hidden" name="_csrf" value="<?= htmlspecialchars($_SESSION['icsrf']) ?>">

    <div class="sec"><div class="sec-title">① 数据库</div>
      <div class="grid3">
        <div class="field"><label>主机</label><input name="host" value="<?= iv('host','127.0.0.1') ?>"></div>
        <div class="field"><label>端口</label><input name="port" type="number" value="<?= iv('port','3306') ?>"></div>
        <div class="field"><label>数据库名</label><input name="dbname" value="<?= iv('dbname','authhub') ?>"></div>
      </div>
      <div class="grid2">
        <div class="field"><label>用户名</label><input name="dbuser" required></div>
        <div class="field"><label>密码</label><input name="dbpass" type="password"></div>
      </div>
    </div>

    <div class="sec"><div class="sec-title">② 管理员与站点</div>
      <div class="field"><label for="site_url">站点 URL（用于邮件中的链接）</label>
        <input id="site_url" name="site_url" placeholder="https://auth.example.com/authhub"></div>
      <div class="field"><label for="admin_email">管理员邮箱 *</label>
        <input id="admin_email" name="admin_email" type="email" required value="<?= iv('admin_email') ?>">
        <p class="hint">此邮箱即为管理员身份。管理员验证邮件将<b>发送到这个邮箱自己</b>。</p></div>
      <div class="field"><label for="admin_pass">管理员密码 *（至少 8 位）</label>
        <input id="admin_pass" name="admin_pass" type="password" required minlength="8"></div>
    </div>

    <div class="sec"><div class="sec-title">③ 邮件服务（SMTP）</div>
      <div class="grid3">
        <div class="field"><label>加密方式</label>
          <select name="smtp_secure">
            <option value="ssl">SSL（隐式，通常 465）</option>
            <option value="tls" selected>TLS/STARTTLS（通常 587）</option>
            <option value="none">无加密（通常 25）</option>
          </select></div>
        <div class="field"><label>端口</label><input name="smtp_port" type="number" placeholder="587"></div>
        <div class="field"><label>SMTP 主机</label><input name="smtp_host" placeholder="smtp.example.com"></div>
      </div>
      <div class="grid2">
        <div class="field"><label>SMTP 用户名（默认同管理员邮箱）</label><input name="smtp_user" placeholder="留空则使用管理员邮箱"></div>
        <div class="field"><label>SMTP 密码 / 授权码</label><input name="smtp_pass" type="password"></div>
      </div>
      <div class="grid2">
        <div class="field"><label>发件人地址</label><input name="smtp_from" placeholder="默认同 SMTP 用户名"></div>
        <div class="field"><label>发件人名称</label><input name="smtp_from_name" value="AuthHub"></div>
      </div>
      <p class="hint">QQ 邮箱：smtp.qq.com + 465(SSL)，密码填授权码；Gmail：smtp.gmail.com + 587(TLS)；163：smtp.163.com + 465(SSL)。</p>
    </div>

    <div class="sec"><div class="sec-title">④ 人机验证（hCaptcha · 暗色复选框）</div>
      <div class="grid2">
        <div class="field"><label>Site Key</label><input name="hcaptcha_sitekey" placeholder="留空 = 不启用验证"></div>
        <div class="field"><label>Secret Key</label><input name="hcaptcha_secret" type="password"></div>
      </div>
      <p class="hint">在 dashboard.hcaptcha.com 免费创建站点获取密钥。注册、登录、找回密码均会显示暗色复选框。</p>
    </div>

    <button type="submit" class="btn">开始安装 →</button>
  </form>
<?php endif; ?>
</main>
</body>
</html>
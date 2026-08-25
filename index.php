<?php
require __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/lib/view.php';

if (!empty($_SESSION['uid'])) { header('Location: dashboard.php'); exit; }
page_head('首页');
?>
<main class="card card-wide" style="text-align:center">
  <?= logo_html() ?>
  <h1>一个账号，<span class="grad-text"> everywhere</span></h1>
  <p class="sub">AuthHub 是统一身份认证平台——网站和 App 通过标准 OAuth 2.0 接入，<br>用户只需一个 AuthHub 账号即可处处登录。</p>
  <div style="display:flex;gap:12px;justify-content:center;flex-wrap:wrap;margin-bottom:26px">
    <a class="btn btn-primary" href="login.php">登 录</a>
    <a class="btn btn-ghost" href="register.php">注册账号</a>
  </div>
  <p class="hint">开发者？<a href="apps.php" style="color:var(--accent);text-decoration:none;font-weight:600">进入控制台创建应用 →</a></p>
</main>
<?php page_foot();
<?php
/** AuthHub 配置模板 —— install.php 会生成 config.php，本文件仅供手动部署参考。 */
return [
    'db' => [
        'host' => '127.0.0.1', 'port' => 3306,
        'name' => 'authhub',   'user' => 'root', 'pass' => '',
        'charset' => 'utf8mb4',
    ],
    // 应用密钥（会话指纹 HMAC），请替换为 bin2hex(random_bytes(32)) 的输出
    'app_key' => '557ba6a8f4fed9a0831b6fa2fb8f2a0899ef3f0c049a24a4d968b6f41a3421aa',
    'session' => ['name' => 'AUTHHUBSESS', 'idle_timeout' => 604800, 'absolute_time' => 2592000], // 空闲7天 / 绝对30天
    // 对外展示的站点 URL（可选）
    'issuer' => 'https://auth.example.com',
    // ★ 管理员邮箱：管理员验证邮件会发到此邮箱（自己给自己发）
    'admin_email' => '',
    // SMTP 邮件服务（ssl=隐式465 / tls=STARTTLS 587 / none=25；留空 host 则不启用邮件功能）
    'smtp' => [
        'host' => '', 'port' => 587, 'secure' => 'tls',
        'user' => '', 'pass' => '',
        'from_email' => '', 'from_name' => 'AuthHub',
    ],
    // hCaptcha 人机验证（dark theme）。sitekey 留空则不启用
    'hcaptcha' => [
        'enabled' => false,
        'sitekey' => '',
        'secret'  => '',
    ],
];

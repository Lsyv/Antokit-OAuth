<?php
/** AuthHub 配置模板 —— install.php 会生成 config.php，本文件仅供手动部署参考。 */
return [
    'db' => [
        'host' => '127.0.0.1', 'port' => 3306,
        'name' => 'authhub',   'user' => 'root', 'pass' => '',
        'charset' => 'utf8mb4',
    ],
    // 应用密钥（会话指纹 HMAC），请替换为 bin2hex(random_bytes(32)) 的输出
    'app_key' => 'CHANGE_ME',
    'session' => ['name' => 'AUTHHUBSESS', 'idle_timeout' => 1800, 'absolute_time' => 43200],
    // 站点 URL（邮件中的链接使用；留空则自动探测）
    'issuer' => 'https://auth.example.com/authhub',

    // ★ 管理员邮箱：即管理员账号本身；管理员验证邮件发到此邮箱（自己给自己发）
    'admin_email' => 'admin@example.com',

    // SMTP 邮件服务（支持 ssl / tls / none）
    'smtp' => [
        'host'       => 'smtp.qq.com',
        'port'       => 465,
        'secure'     => 'ssl',          // ssl | tls | none
        'user'       => 'admin@example.com',
        'pass'       => 'SMTP密码或授权码',
        'from_email' => 'admin@example.com',
        'from_name'  => 'AuthHub',
    ],

    // hCaptcha 人机验证（Checkbox · dark theme）。sitekey 留空则不启用
    'hcaptcha' => [
        'enabled' => false,
        'sitekey' => '',
        'secret'  => '',
    ],
];
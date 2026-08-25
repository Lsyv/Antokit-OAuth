<?php
declare(strict_types=1);

/**
 * hCaptcha 校验（Checkbox · dark theme）
 * 文档：https://docs.hcaptcha.com/
 */

/** 未配置时返回 null；已配置则返回组件 HTML（暗色复选框主题） */
function hcaptcha_widget(array $config): ?string
{
    $sitekey = trim((string)($config['hcaptcha']['sitekey'] ?? ''));
    if ($sitekey === '') return null; // 未配置 = 不启用，前后端行为一致
    return '<div class="h-captcha" data-theme="dark" data-sitekey="' . htmlspecialchars($sitekey) . '"></div>'
         . '<script src="https://js.hcaptcha.com/1/api.js" async defer></script>';
}

/**
 * 服务端校验。未配置则跳过；失败时设置 $error 并返回 false。
 * 用法：if (!hcaptcha_verify($config, $error)) { ... }
 */
function hcaptcha_verify(array $config, &$error = null): bool
{
    $secret = trim((string)($config['hcaptcha']['secret'] ?? ''));
    if ($secret === '') return true; // 未配置 = 不启用

    $token = $_POST['h-captcha-response'] ?? '';
    if (!is_string($token) || $token === '') {
        $error = '请完成人机验证。';
        return false;
    }
    $ch = curl_init('https://api.hcaptcha.com/siteverify');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query([
            'secret'   => $secret,
            'response' => $token,
            'remoteip' => $_SERVER['REMOTE_ADDR'] ?? '',
        ]),
        CURLOPT_TIMEOUT => 10,
    ]);
    $resp = json_decode((string)curl_exec($ch), true);
    curl_close($ch);

    if (!empty($resp['success'])) return true;
    $codes = implode(', ', (array)($resp['error-codes'] ?? []));
    $error = '人机验证未通过' . ($codes ? '（' . $codes . '）' : '') . '，请重试。';
    return false;
}
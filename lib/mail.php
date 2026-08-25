<?php
declare(strict_types=1);

/**
 * 零依赖 SMTP 邮件客户端。
 * 支持：SSL(隐式465) / STARTTLS(587) / 无加密(25)，AUTH LOGIN。
 */

function send_mail(array $config, string $to, string $subject, string $html): void
{
    $s = $config['smtp'] ?? null;
    if (!$s || empty($s['host'])) {
        throw new RuntimeException('邮件服务未配置，请在 install.php 中填写 SMTP 信息。');
    }

    $secure = $s['secure'] ?? 'none';           // ssl | tls | none
    $host   = ($secure === 'ssl' ? 'ssl://' : '') . $s['host'];
    $port   = (int)($s['port'] ?: 25);
    $timeout = 12;

    $fp = @stream_socket_client("$host:$port", $errno, $errstr, $timeout);
    if (!$fp) throw new RuntimeException("SMTP 连接失败: $errstr");
    stream_set_timeout($fp, $timeout);

    $read = function () use ($fp): string {
        $data = '';
        while (($line = fgets($fp, 515)) !== false) {
            $data .= $line;
            if (isset($line[3]) && $line[3] === ' ') break; // 末行形如 "250 OK"
        }
        return $data;
    };
    $cmd = function (string $c, array $expect) use ($fp, $read): string {
        fwrite($fp, $c . "\r\n");
        $r = $read();
        if (!in_array((int)substr($r, 0, 3), $expect, true)) {
            throw new RuntimeException("SMTP 命令失败 [$c]: " . trim($r));
        }
        return $r;
    };

    $greeting = $read();
    if ((int)substr($greeting, 0, 3) !== 220) throw new RuntimeException('SMTP 握手失败: ' . trim($greeting));

    $ehloHost = $_SERVER['SERVER_NAME'] ?? 'localhost';
    $cmd('EHLO ' . $ehloHost, [250]);

    // STARTTLS
    if ($secure === 'tls') {
        $cmd('STARTTLS', [220]);
        if (!stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
            throw new RuntimeException('STARTTLS 加密协商失败');
        }
        $cmd('EHLO ' . $ehloHost, [250]);
    }

    // 认证
    if (!empty($s['user'])) {
        $cmd('AUTH LOGIN', [334]);
        $cmd(base64_encode($s['user']), [334]);
        $cmd(base64_encode((string)$s['pass']), [235]);
    }

    $from = $s['from_email'] ?? $s['user'];
    $fromName = $s['from_name'] ?? 'AuthHub';

    $cmd('MAIL FROM:<' . $from . '>', [250]);
    $cmd('RCPT TO:<' . $to . '>', [250, 251]);
    $cmd('DATA', [354]);

    $headers = [
        'From: =?UTF-8?B?' . base64_encode($fromName) . '?= <' . $from . '>',
        'To: <' . $to . '>',
        'Subject: =?UTF-8?B?' . base64_encode($subject) . '?=',
        'MIME-Version: 1.0',
        'Content-Type: text/html; charset=UTF-8',
        'Content-Transfer-Encoding: base64',
        'Date: ' . date('r'),
        'Message-ID: <' . bin2hex(random_bytes(12)) . '@' . ($s['host'] ?? 'authhub') . '>',
    ];
    $body = implode("\r\n", $headers) . "\r\n\r\n"
          . chunk_split(base64_encode($html));
    // 数据中的单独 "." 需要转义（RFC 5321 §4.5.2）
    $body = preg_replace('/^\./m', '..', $body);
    fwrite($fp, $body . "\r\n.\r\n");
    $r = $read();
    if ((int)substr($r, 0, 3) !== 250) throw new RuntimeException('邮件被拒绝: ' . trim($r));

    fwrite($fp, "QUIT\r\n");
    fclose($fp);
}

/** 发送 AuthHub 风格的验证/通知邮件 */
function send_authhub_mail(array $config, string $to, string $title, string $bodyHtml, string $actionUrl = '', string $actionText = ''): void
{
    $btn = $actionUrl
        ? '<a href="' . htmlspecialchars($actionUrl) . '" style="display:inline-block;background:#6366f1;color:#fff;'
          . 'padding:12px 28px;border-radius:9px;text-decoration:none;font-weight:600;margin-top:22px">'
          . htmlspecialchars($actionText ?: '确认操作') . '</a>'
        : '';
    $html = '<div style="font-family:-apple-system,Segoe UI,PingFang SC,sans-serif;background:#f4f5f7;padding:36px 16px">
<div style="max-width:480px;margin:0 auto;background:#fff;border-radius:16px;padding:38px 34px">
<h2 style="margin:0 0 6px;font-size:21px">AuthHub</h2>
<p style="color:#666;font-size:14px;margin:0 0 20px">' . htmlspecialchars($title) . '</p>
<p style="font-size:14.5px;line-height:1.7;color:#333">' . $bodyHtml . '</p>'
. $btn .
'<p style="color:#999;font-size:12px;margin-top:30px">如果按钮无法点击，请复制以下链接到浏览器：<br>'
. ($actionUrl ? '<span style="word-break:break-all">' . htmlspecialchars($actionUrl) . '</span>' : '')
. '</p></div></div>';
    send_mail($config, $to, $title, $html);
}
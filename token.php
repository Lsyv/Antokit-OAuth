<?php
declare(strict_types=1);
/**
 * OAuth 2.0 令牌端点 POST /token.php
 * 支持 grant_type=authorization_code 与 refresh_token
 * 机密客户端（web）需 HTTP Basic 或 POST body 提供 client_secret
 */
require __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/lib/oauth_server.php';

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    oauth_error('invalid_request', '仅支持 POST');
}
header('Cache-Control: no-store');

$client_id = (string)($_POST['client_id'] ?? '');
// 支持 HTTP Basic 认证
if (!$client_id && isset($_SERVER['PHP_AUTH_USER'])) {
    $client_id = $_SERVER['PHP_AUTH_USER'];
}
$client_secret = (string)($_POST['client_secret'] ?? ($_SERVER['PHP_AUTH_PW'] ?? ''));

$app = app_find($client_id);
if (!$app) {
    oauth_error('invalid_client', '未知客户端', null);
    // never returns
}

// web 客户端必须验证 secret；native（public client）不使用 secret
if ($app['type'] === 'confidential') {
    if (!$client_secret || empty($app['client_secret_hash'])
        || !hash_equals((string)$app['client_secret_hash'], hash('sha256', $client_secret))) {
        http_response_code(401);
        header('WWW-Authenticate: Basic realm="authhub"');
        oauth_error('invalid_client', '客户端认证失败', null);
    }
}

$grant = (string)($_POST['grant_type'] ?? '');

if ($grant === 'authorization_code') {
    $code     = (string)($_POST['code'] ?? '');
    $redirect = (string)($_POST['redirect_uri'] ?? '');
    $verifier = (string)($_POST['code_verifier'] ?? '');

    $row = auth_code_consume($code);
    if (!$row || (int)$row['app_id'] !== (int)$app['id']) {
        oauth_error('invalid_grant', '授权码无效或已过期', null);
    }
    if ($redirect !== (string)$row['redirect_uri']) {
        oauth_error('invalid_grant', 'redirect_uri 不匹配', null);
    }
    if (!empty($row['pkce_challenge'])) {
        if ($verifier === '' || !pkce_verify($row['pkce_challenge'], $row['pkce_method'], $verifier)) {
            oauth_error('invalid_grant', 'PKCE 校验失败', null);
        }
    }

    $withRefresh = str_contains((string)$row['scope'], 'offline_access')
                || $app['type'] === 'native'; // 原生应用默认可离线
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(token_issue((int)$row['user_id'], (int)$app['id'], (string)$row['scope'], $withRefresh),
        JSON_UNESCAPED_UNICODE);
    exit;
}

if ($grant === 'refresh_token') {
    $tokens = token_refresh((string)($_POST['refresh_token'] ?? ''), (int)$app['id']);
    if (!$tokens) {
        oauth_error('invalid_grant', 'refresh_token 无效或已过期', null);
    }
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($tokens, JSON_UNESCAPED_UNICODE);
    exit;
}

oauth_error('unsupported_grant_type', '仅支持 authorization_code 与 refresh_token');
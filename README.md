# AuthHub — 自建 OAuth 2.0 统一身份认证平台

你的网站/应用本身就是「Google 账号」：任何第三方网站和 App 通过标准 **OAuth 2.0 授权码流程**接入 AuthHub，用户使用一个 AuthHub 账号处处登录。

PHP 8.1+ · MySQL/MariaDB · Apache · 零依赖

## ✨ 功能
- **完整 OAuth 2.0 授权服务器**（RFC 6749）：`authorize.php` / `token.php` / `userinfo.php`
- 支持**网站**（机密客户端 + client_secret）与**软件 App**（公开客户端 + 强制 PKCE，RFC 8252）
- refresh_token 刷新与轮换、授权码一次性使用 + 重放检测自动吊销
- 用户同意授权页、已授权应用管理（随时撤销）
- 开发者控制台：创建应用、Client ID/Secret 管理、密钥轮换
- 安全：Argon2id、CSRF、会话加固、登录限速、CSP 等安全头

## 🚀 安装
1. 将 `authhub/` 放入 Apache 站点根目录。
2. 访问 `http://your-host/authhub/install.php` 完成安装（自动建库建表）。
3. **删除 install.php**。
4. 开发者在「开发者控制台」创建应用，获得 Client ID / Secret。

## 🔌 第三方接入指南

### 网站（Web，机密客户端）
```
1. 跳转授权：
   GET https://your-host/authhub/authorize.php
       ?response_type=code
       &client_id=ah_xxxx
       &redirect_uri=https://yoursite.com/callback   （必须精确匹配注册值）
       &scope=openid profile email offline_access
       &state=随机字符串                              （防 CSRF）

2. 用户同意后回跳 yoursite.com/callback?code=...&state=...
   校验 state 后换取令牌：
   POST https://your-host/authhub/token.php
   Content-Type: application/x-www-form-urlencoded

   grant_type=authorization_code
   &code=上一步的code
   &redirect_uri=https://yoursite.com/callback
   &client_id=ah_xxxx
   &client_secret=ahs_xxxx

   → {"access_token":"...","token_type":"Bearer","expires_in":3600,"refresh_token":"..."}

3. 获取用户信息：
   GET https://your-host/authhub/userinfo.php
   Authorization: Bearer <access_token>
   → {"sub":"1","name":"张三","email":"z@x.com",...}
```

### 软件 App（Native，公开客户端 — 必须使用 PKCE）
```
1. App 内生成 code_verifier = 随机43~128位字符串
   code_challenge = BASE64URL(SHA256(code_verifier))

2. 打开系统浏览器：
   GET .../authorize.php?response_type=code&client_id=ah_xxxx
       &redirect_uri=myapp://callback        （自定义 scheme 或 http://127.0.0.1:端口）
       &scope=openid profile email offline_access
       &state=随机
       &code_challenge=上一步值
       &code_challenge_method=S256

3. 通过 scheme 唤起 App 拿到 code，换令牌时附 code_verifier（无需 secret）。
4. 刷新令牌：POST token.php, grant_type=refresh_token&refresh_token=...
```

### scope 说明
| scope | 含义 |
|---|---|
| openid | 用户唯一 ID (sub) |
| profile | 昵称、头像 |
| email | 邮箱地址 |
| offline_access | 获得 refresh_token |

## 📄 文档
详见 `docs/开发文档.docx`。
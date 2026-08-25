<?php
declare(strict_types=1);
/** 页面模板辅助函数。 */

function page_head(string $title, bool $center = true): void
{
    echo '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8">'
       . '<meta name="viewport" content="width=device-width, initial-scale=1">'
       . '<meta name="color-scheme" content="dark dark">'
       . '<title>' . e($title) . ' · AuthHub</title>'
       . '<link rel="stylesheet" href="assets/style.css"></head><body>'
       . ($center ? '<div class="center-wrap">' : '');
}

function page_foot(bool $center = true): void
{
    echo ($center ? '</div>' : '')
       . '<footer class="note">AuthHub · 统一身份认证平台</footer></body></html>';
}

function logo_html(): string
{
    return '<a class="logo" href="index.php"><span class="logo-mark">A</span><span class="logo-name">AuthHub</span></a>';
}
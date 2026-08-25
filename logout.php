<?php
require __DIR__ . '/bootstrap.php';
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') csrf_verify();
$_SESSION = [];
session_destroy();
header('Location: login.php');
exit;
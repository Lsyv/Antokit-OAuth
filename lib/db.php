<?php
declare(strict_types=1);
/** PDO 单例。所有查询一律使用服务端预处理语句。 */

function db_init(array $config): void
{
    static $done = false;
    if ($done) return;
    $d = $config['db'];
    $dsn = "mysql:host={$d['host']};port={$d['port']};dbname={$d['name']};charset={$d['charset']}";
    $GLOBALS['__db'] = new PDO($dsn, $d['user'], $d['pass'], [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ]);
    $done = true;
}

function db(): PDO { return $GLOBALS['__db']; }

function db_query(string $sql, array $params = []): PDOStatement
{
    $stmt = db()->prepare($sql);
    $stmt->execute($params);
    return $stmt;
}
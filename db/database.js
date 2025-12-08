import sqlite3 from 'sqlite3';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const db = new sqlite3.Database(join(__dirname, 'auth.db'), (err) => {
    if (err) {
        console.error('❌ Ошибка подключения к БД:', err);
    }
});

// Промисификация для удобства
const runAsync = (sql, params = []) => {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function (err) {
            if (err) reject(err);
            else resolve(this);
        });
    });
};

const getAsync = (sql, params = []) => {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
};

const allAsync = (sql, params = []) => {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
};

/**
 * Инициализация базы данных
 */
export async function initDatabase() {
    try {
        // Включаем поддержку внешних ключей
        await runAsync('PRAGMA foreign_keys = ON');

        // Таблица пользователей
        await runAsync(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

        // Таблица токенов
        await runAsync(`
      CREATE TABLE IF NOT EXISTS tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        access_token TEXT UNIQUE NOT NULL,
        refresh_token TEXT UNIQUE NOT NULL,
        ip_address TEXT NOT NULL,
        allowed_ips TEXT NOT NULL,
        expires_at DATETIME NOT NULL,
        refresh_expires_at DATETIME NOT NULL,
        is_revoked INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

        // Индексы для быстрого поиска
        await runAsync('CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id)');
        await runAsync('CREATE INDEX IF NOT EXISTS idx_tokens_access_token ON tokens(access_token)');
        await runAsync('CREATE INDEX IF NOT EXISTS idx_tokens_refresh_token ON tokens(refresh_token)');
        await runAsync('CREATE INDEX IF NOT EXISTS idx_tokens_is_revoked ON tokens(is_revoked)');

        console.log('✅ База данных инициализирована');
    } catch (error) {
        console.error('❌ Ошибка инициализации БД:', error);
        throw error;
    }
}

export { db, runAsync, getAsync, allAsync };

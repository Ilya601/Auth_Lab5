import { runAsync, getAsync, allAsync } from './database.js';
import bcrypt from 'bcrypt';

const SALT_ROUNDS = 10;

/**
 * Создать нового пользователя
 */
export async function createUser(username, password) {
  const passwordHash = bcrypt.hashSync(password, SALT_ROUNDS);
  
  try {
    const result = await runAsync(
      'INSERT INTO users (username, password_hash) VALUES (?, ?)',
      [username, passwordHash]
    );
    
    return {
      id: result.lastID,
      username
    };
  } catch (error) {
    if (error.message.includes('UNIQUE constraint failed')) {
      throw new Error('Пользователь с таким username уже существует');
    }
    throw error;
  }
}

/**
 * Найти пользователя по username
 */
export async function findUserByUsername(username) {
  return await getAsync('SELECT * FROM users WHERE username = ?', [username]);
}

/**
 * Найти пользователя по ID
 */
export async function findUserById(id) {
  return await getAsync('SELECT id, username, created_at FROM users WHERE id = ?', [id]);
}

/**
 * Проверить пароль
 */
export function verifyPassword(password, passwordHash) {
  return bcrypt.compareSync(password, passwordHash);
}

/**
 * Получить всех пользователей (без паролей)
 */
export async function getAllUsers() {
  return await allAsync('SELECT id, username, created_at FROM users');
}

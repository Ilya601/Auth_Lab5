import { runAsync, getAsync, allAsync } from './database.js';

export async function saveTokens(userId, accessToken, refreshToken, ipAddress, allowedIps, accessExpiresAt, refreshExpiresAt) {
  const allowedIpsJson = JSON.stringify(allowedIps);
  
  const result = await runAsync(
    `INSERT INTO tokens (user_id, access_token, refresh_token, ip_address, allowed_ips, expires_at, refresh_expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [userId, accessToken, refreshToken, ipAddress, allowedIpsJson, accessExpiresAt, refreshExpiresAt]
  );
  
  return result.lastID;
}

/**
 * Найти токен по access token
 */
export async function findByAccessToken(accessToken) {
  const token = await getAsync(
    'SELECT * FROM tokens WHERE access_token = ? AND is_revoked = 0',
    [accessToken]
  );
  
  if (token && token.allowed_ips) {
    token.allowed_ips = JSON.parse(token.allowed_ips);
  }
  return token;
}

/**
 * Найти токен по refresh token
 */
export async function findByRefreshToken(refreshToken) {
  const token = await getAsync(
    'SELECT * FROM tokens WHERE refresh_token = ? AND is_revoked = 0',
    [refreshToken]
  );
  
  if (token && token.allowed_ips) {
    token.allowed_ips = JSON.parse(token.allowed_ips);
  }
  return token;
}

/**
 * Отозвать все токены пользователя
 */
export async function revokeAllUserTokens(userId) {
  return await runAsync(
    'UPDATE tokens SET is_revoked = 1 WHERE user_id = ? AND is_revoked = 0',
    [userId]
  );
}

/**
 * Отозвать конкретный токен
 */
export async function revokeToken(tokenId) {
  return await runAsync('UPDATE tokens SET is_revoked = 1 WHERE id = ?', [tokenId]);
}

/**
 * Отозвать токен по refresh token
 */
export async function revokeByRefreshToken(refreshToken) {
  return await runAsync('UPDATE tokens SET is_revoked = 1 WHERE refresh_token = ?', [refreshToken]);
}

/**
 * Получить все активные токены пользователя
 */
export async function getUserActiveTokens(userId) {
  const tokens = await allAsync(
    `SELECT id, ip_address, allowed_ips, expires_at, created_at
     FROM tokens 
     WHERE user_id = ? AND is_revoked = 0 AND expires_at > datetime('now')
     ORDER BY created_at DESC`,
    [userId]
  );
  
  return tokens.map(token => ({
    ...token,
    allowed_ips: JSON.parse(token.allowed_ips)
  }));
}

/**
 * Очистить истекшие токены
 */
export async function cleanupExpiredTokens() {
  return await runAsync("DELETE FROM tokens WHERE refresh_expires_at < datetime('now')");
}

/**
 * Проверить, не отозван ли токен
 */
export async function isTokenValid(accessToken) {
  const result = await getAsync(
    `SELECT COUNT(*) as count 
     FROM tokens 
     WHERE access_token = ? AND is_revoked = 0 AND expires_at > datetime('now')`,
    [accessToken]
  );
  
  return result.count > 0;
}

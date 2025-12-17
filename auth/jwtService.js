import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { normalizeIp } from '../utils/ipUtils.js';
import { saveTokens, findByRefreshToken, revokeAllUserTokens, isTokenValid } from '../db/tokenRepository.js';

const JWT_SECRET = process.env.JWT_SECRET || 'default-secret-key';
const REFRESH_SECRET = process.env.REFRESH_SECRET || 'default-refresh-secret';

export async function createTokenPair(userId, username, ipAddress, allowedIps = null) {
  const normalizedIp = normalizeIp(ipAddress);
  const ips = allowedIps || [normalizedIp];
  
  // Access token (короткий срок жизни)
  const accessPayload = {
    userId,
    username,
    ip: normalizedIp,
    allowedIps: ips,
    type: 'access',
    jti: crypto.randomUUID() // Уникальный ID токена
  };
  
  const accessToken = jwt.sign(accessPayload, JWT_SECRET, {
    expiresIn: '30s' // 15 минут
  });
  
  // Refresh token (длинный срок жизни)
  const refreshPayload = {
    userId,
    username,
    ip: normalizedIp,
    allowedIps: ips,
    type: 'refresh',
    jti: crypto.randomUUID()
  };
  
  const refreshToken = jwt.sign(refreshPayload, REFRESH_SECRET, {
    expiresIn: '7d' // 7 дней
  });
  
  // Вычисляем время истечения
  const accessExpiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();
  const refreshExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
  
  // Отзываем все старые токены пользователя
  await revokeAllUserTokens(userId);
  
  // Сохраняем новые токены в БД
  await saveTokens(userId, accessToken, refreshToken, normalizedIp, ips, accessExpiresAt, refreshExpiresAt);
  
  return {
    accessToken,
    refreshToken,
    expiresIn: 900, // 15 минут в секундах
    tokenType: 'Bearer'
  };
}

/**
 * Обновить токены используя refresh token
 */
export async function refreshTokenPair(refreshToken, currentIp) {
  try {
    // Верифицируем refresh token
    const decoded = jwt.verify(refreshToken, REFRESH_SECRET);
    
    if (decoded.type !== 'refresh') {
      throw new Error('Неверный тип токена');
    }
    
    // Проверяем, что токен есть в БД и не отозван
    const tokenRecord = await findByRefreshToken(refreshToken);
    
    if (!tokenRecord) {
      throw new Error('Refresh token не найден или отозван');
    }
    
    // Проверяем IP
    const normalizedCurrentIp = normalizeIp(currentIp);
    const isIpValid = tokenRecord.allowed_ips.some(allowedIp => {
      if (allowedIp === normalizedCurrentIp) return true;
      if (allowedIp.includes('*')) {
        const pattern = allowedIp.replace(/\./g, '\\.').replace(/\*/g, '.*');
        return new RegExp(`^${pattern}$`).test(normalizedCurrentIp);
      }
      return false;
    });
    
    if (!isIpValid) {
      throw new Error('IP-адрес не соответствует токену');
    }
    
    // Создаем новую пару токенов
    return await createTokenPair(decoded.userId, decoded.username, currentIp, tokenRecord.allowed_ips);
  } catch (error) {
    throw new Error(`Ошибка обновления токена: ${error.message}`);
  }
}

/**
 * Верифицировать JWT токен
 */
export function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    throw new Error(`Ошибка верификации токена: ${error.message}`);
  }
}

/**
 * Проверить токен и IP-адрес
 */
export async function validateTokenWithIp(token, currentIp) {
  try {
    // Проверяем, что токен не отозван в БД
    const isValid = await isTokenValid(token);
    if (!isValid) {
      return {
        valid: false,
        error: 'Токен отозван или истек',
        decoded: null
      };
    }
    
    const decoded = verifyToken(token);
    
    if (decoded.type !== 'access') {
      return {
        valid: false,
        error: 'Неверный тип токена',
        decoded: null
      };
    }
    
    const normalizedCurrentIp = normalizeIp(currentIp);
    
    // Проверяем список разрешенных IP
    const allowedIps = decoded.allowedIps || [decoded.ip];
    const isIpValid = allowedIps.some(allowedIp => {
      if (allowedIp === normalizedCurrentIp) return true;
      
      if (allowedIp.includes('*')) {
        const pattern = allowedIp.replace(/\./g, '\\.').replace(/\*/g, '.*');
        const regex = new RegExp(`^${pattern}$`);
        return regex.test(normalizedCurrentIp);
      }
      
      return false;
    });
    
    if (!isIpValid) {
      return {
        valid: false,
        error: 'IP-адрес не соответствует токену',
        decoded: null
      };
    }
    
    return {
      valid: true,
      error: null,
      decoded
    };
  } catch (error) {
    return {
      valid: false,
      error: error.message,
      decoded: null
    };
  }
}

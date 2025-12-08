/**
 * Утилиты для работы с IP-адресами
 */

/**
 * Получить реальный IP-адрес клиента
 * @param {Object} req - Express request объект
 * @returns {string} IP-адрес клиента
 */
export function getClientIp(req) {
  // Проверяем заголовки прокси
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }
  
  const realIp = req.headers['x-real-ip'];
  if (realIp) {
    return realIp;
  }
  
  // Fallback на socket IP
  return req.socket.remoteAddress || req.connection.remoteAddress;
}

/**
 * Проверить, находится ли IP в списке разрешенных
 * @param {string} ip - IP-адрес для проверки
 * @param {Array<string>} allowedIps - Массив разрешенных IP или CIDR
 * @returns {boolean}
 */
export function isIpAllowed(ip, allowedIps) {
  if (!allowedIps || allowedIps.length === 0) {
    return true;
  }
  
  // Нормализация IPv6 localhost
  const normalizedIp = ip === '::1' || ip === '::ffff:127.0.0.1' ? '127.0.0.1' : ip;
  
  return allowedIps.some(allowedIp => {
    // Точное совпадение
    if (allowedIp === normalizedIp) {
      return true;
    }
    
    // Поддержка wildcard (например, 192.168.1.*)
    if (allowedIp.includes('*')) {
      const pattern = allowedIp.replace(/\./g, '\\.').replace(/\*/g, '.*');
      const regex = new RegExp(`^${pattern}$`);
      return regex.test(normalizedIp);
    }
    
    return false;
  });
}

/**
 * Нормализовать IP-адрес
 * @param {string} ip - IP-адрес
 * @returns {string} Нормализованный IP
 */
export function normalizeIp(ip) {
  if (ip === '::1' || ip === '::ffff:127.0.0.1') {
    return '127.0.0.1';
  }
  if (ip && ip.startsWith('::ffff:')) {
    return ip.substring(7);
  }
  return ip;
}

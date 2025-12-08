import { validateTokenWithIp } from '../auth/jwtService.js';
import { getClientIp } from '../utils/ipUtils.js';

/**
 * Middleware для проверки JWT токена с IP-ограничением
 */
export async function authenticateWithIp(req, res, next) {
  try {
    // Получаем токен из заголовка
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        error: 'Токен не предоставлен'
      });
    }
    
    const token = authHeader.substring(7);
    const clientIp = getClientIp(req);
    
    // Валидируем токен и IP
    const validation = await validateTokenWithIp(token, clientIp);
    
    if (!validation.valid) {
      return res.status(403).json({
        success: false,
        error: validation.error,
        clientIp: clientIp
      });
    }
    
    // Добавляем данные пользователя в request
    req.user = validation.decoded;
    req.clientIp = clientIp;
    
    next();
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: 'Ошибка аутентификации'
    });
  }
}

/**
 * Опциональная аутентификация (не блокирует запрос)
 */
export async function optionalAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      const clientIp = getClientIp(req);
      
      const validation = await validateTokenWithIp(token, clientIp);
      
      if (validation.valid) {
        req.user = validation.decoded;
        req.clientIp = clientIp;
      }
    }
    
    next();
  } catch (error) {
    next();
  }
}

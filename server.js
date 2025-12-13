import express from 'express';
import dotenv from 'dotenv';
import { initDatabase } from './db/database.js';
import { createTokenPair, refreshTokenPair } from './auth/jwtService.js';
import { authenticateWithIp, optionalAuth } from './middleware/authMiddleware.js';
import { getClientIp } from './utils/ipUtils.js';
import { createUser, findUserByUsername, verifyPassword, findUserById } from './db/userRepository.js';
import { getUserActiveTokens, revokeAllUserTokens, cleanupExpiredTokens } from './db/tokenRepository.js';

dotenv.config();

// Инициализация БД
await initDatabase();

// Очистка истекших токенов при старте
await cleanupExpiredTokens();

// Периодическая очистка истекших токенов (каждый час)
setInterval(async () => {
  const result = await cleanupExpiredTokens();
  if (result.changes > 0) {
    console.log(`🧹 Очищено истекших токенов: ${result.changes}`);
  }
}, 60 * 60 * 1000);

export const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Логирование запросов
app.use((req, res, next) => {
  console.log(`${req.method} ${req.path} - IP: ${getClientIp(req)}`);
  next();
});

/**
 * POST /api/auth/register
 * Регистрация нового пользователя
 */
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        error: 'Username и password обязательны'
      });
    }
    
    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        error: 'Пароль должен быть не менее 6 символов'
      });
    }
    
    const user = await createUser(username, password);
    
    res.status(201).json({
      success: true,
      message: 'Пользователь успешно зарегистрирован',
      user: {
        id: user.id,
        username: user.username
      }
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/auth/login
 * Вход и получение токенов
 */
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password, allowedIps } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        error: 'Username и password обязательны'
      });
    }
    
    const user = await findUserByUsername(username);
    
    if (!user || !verifyPassword(password, user.password_hash)) {
      return res.status(401).json({
        success: false,
        error: 'Неверные учетные данные'
      });
    }
    
    const clientIp = getClientIp(req);
    const ips = allowedIps || null;
    
    // Создаем пару токенов (старые автоматически отзываются)
    const tokens = await createTokenPair(user.id, user.username, clientIp, ips);
    
    res.json({
      success: true,
      message: 'Вход выполнен успешно',
      ...tokens,
      user: {
        id: user.id,
        username: user.username
      },
      ip: clientIp,
      allowedIps: ips || [clientIp]
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/auth/refresh
 * Обновление токенов
 */
app.post('/api/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        error: 'Refresh token обязателен'
      });
    }
    
    const clientIp = getClientIp(req);
    
    // Создаем новую пару токенов (старые автоматически отзываются)
    const tokens = await refreshTokenPair(refreshToken, clientIp);
    
    res.json({
      success: true,
      message: 'Токены обновлены',
      ...tokens
    });
  } catch (error) {
    res.status(401).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/auth/logout
 * Выход (отзыв всех токенов)
 */
app.post('/api/auth/logout', authenticateWithIp, async (req, res) => {
  try {
    await revokeAllUserTokens(req.user.userId);
    
    res.json({
      success: true,
      message: 'Выход выполнен успешно'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/protected
 * Защищенный маршрут - требует валидный токен с правильным IP
 */
app.get('/api/protected', authenticateWithIp, (req, res) => {
  res.json({
    success: true,
    message: 'Доступ разрешен',
    user: {
      userId: req.user.userId,
      username: req.user.username
    },
    clientIp: req.clientIp,
    allowedIps: req.user.allowedIps
  });
});

/**
 * GET /api/profile
 * Профиль пользователя
 */
app.get('/api/profile', authenticateWithIp, async (req, res) => {
  try {
    const user = await findUserById(req.user.userId);
    const activeTokens = await getUserActiveTokens(req.user.userId);
    
    res.json({
      success: true,
      profile: {
        id: user.id,
        username: user.username,
        createdAt: user.created_at,
        currentIp: req.clientIp,
        allowedIps: req.user.allowedIps,
        activeSessions: activeTokens.length
      },
      sessions: activeTokens
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/public
 * Публичный маршрут с опциональной аутентификацией
 */
app.get('/api/public', optionalAuth, (req, res) => {
  res.json({
    success: true,
    message: 'Публичный маршрутaaaaa',
    authenticated: !!req.user,
    user: req.user ? {
      username: req.user.username,
      ip: req.clientIp
    } : null
  });
});

/**
 * GET /api/info
 * Информация о текущем IP
 */
app.get('/api/info', (req, res) => {
  res.json({
    success: true,
    clientIp: getClientIp(req),
    headers: {
      'x-forwarded-for': req.headers['x-forwarded-for'],
      'x-real-ip': req.headers['x-real-ip']
    }
  });
});

// Обработка 404
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Маршрут не найден'
  });
});

// Обработка ошибок
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    success: false,
    error: 'Внутренняя ошибка сервера'
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Сервер запущен на порту ${PORT}`);
  console.log(`📍 http://localhost:${PORT}`);
  console.log(`🔐 JWT с IP-ограничениями активирован`);
});

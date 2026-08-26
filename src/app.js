const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const pinoHttp = require('pino-http');
const swaggerUi = require('swagger-ui-express');
const YAML = require('js-yaml');
const fs = require('fs');
const path = require('path');

const env = require('./config/env');
const { logger } = require('./utils/audit');
const apiRateLimiter = require('./middleware/apiRateLimiter');
const { notFound, errorHandler } = require('./middleware/errorHandler');

const authRoutes = require('./routes/authRoutes');
const protectedRoutes = require('./routes/protectedRoutes');

function createApp() {
  const app = express();

  app.use(helmet());
  app.use(
    cors({
      origin: env.clientOrigin,
      credentials: true,
    })
  );
  app.use(express.json({ limit: '10kb' })); // small limit: auth payloads are tiny
  app.use(cookieParser());
  if (env.nodeEnv !== 'test') {
    app.use(pinoHttp({ logger, autoLogging: { ignore: (req) => req.url === '/health' } }));
  }
  app.use(apiRateLimiter);

  app.get('/health', (req, res) => res.json({ status: 'ok', env: env.nodeEnv }));

  // OpenAPI docs at /api/docs
  try {
    const specPath = path.join(__dirname, '..', 'openapi.yaml');
    const openapiSpec = YAML.load(fs.readFileSync(specPath, 'utf8'));
    app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(openapiSpec));
  } catch (err) {
    console.warn('[app] could not load openapi.yaml, /api/docs disabled:', err.message);
  }

  app.use('/api/auth', authRoutes);
  app.use('/api', protectedRoutes);

  app.use(notFound);
  app.use(errorHandler);

  return app;
}

module.exports = createApp;

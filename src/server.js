const createApp = require('./app');
const env = require('./config/env');
const { connectDB } = require('./config/db');
const { getRedisClient } = require('./config/redis');

async function start() {
  await connectDB();
  getRedisClient(); // establishes connection eagerly, logs on success

  const app = createApp();
  const server = app.listen(env.port, () => {
    console.log(`[server] listening on port ${env.port} (${env.nodeEnv})`);
  });

  const shutdown = async (signal) => {
    console.log(`[server] received ${signal}, shutting down...`);
    server.close(() => process.exit(0));
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

start().catch((err) => {
  console.error('[server] failed to start:', err);
  process.exit(1);
});

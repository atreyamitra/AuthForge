const env = require('./env');

let client;

function getRedisClient() {
  if (client) return client;

  const Redis = require('ioredis');
  client = new Redis(env.redisUrl, {
    maxRetriesPerRequest: 3,
    lazyConnect: false,
  });
  client.on('error', (err) => console.error('[redis] error', err.message));
  client.on('connect', () => console.log('[redis] connected'));

  return client;
}

async function closeRedisClient() {
  if (client) {
    await client.quit().catch(() => client.disconnect());
    client = undefined;
  }
}

module.exports = { getRedisClient, closeRedisClient };

/**
 * Operator-only path to create/promote an admin. There is deliberately NO
 * HTTP endpoint that can create the first admin; public signup is always
 * role "user". Run with direct access to the database:
 *
 *   MONGO_URI=... JWT_ACCESS_SECRET=... JWT_REFRESH_SECRET=... \
 *   ADMIN_EMAIL=a@example.com ADMIN_PASSWORD='...' node scripts/create-admin.js
 *
 * Existing admins can afterwards promote others via PATCH /api/admin/users/:id/role.
 */
const User = require('../src/models/User');
const { connectDB, disconnectDB } = require('../src/config/db');

async function main() {
  const email = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  const password = process.env.ADMIN_PASSWORD || '';
  if (!email || Buffer.byteLength(password) < 8 || Buffer.byteLength(password) > 72) {
    throw new Error('ADMIN_EMAIL and ADMIN_PASSWORD (8-72 bytes) are required');
  }
  await connectDB();
  const existing = await User.findOne({ email });
  if (existing) {
    await User.updateOne({ _id: existing._id }, { role: 'admin', $inc: { sessionVersion: 1 } });
    console.log(`Promoted existing user ${email} to admin`);
  } else {
    await User.create({ email, passwordHash: await User.hashPassword(password), role: 'admin' });
    console.log(`Created admin ${email}`);
  }
  await disconnectDB();
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});

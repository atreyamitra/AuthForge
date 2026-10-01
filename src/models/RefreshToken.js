const mongoose = require('mongoose');

const refreshTokenSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    tokenId: { type: String, required: true, unique: true }, // jti claim
    family: { type: String, required: true, index: true }, // one login = one family; rotation keeps it
    sessionVersion: { type: Number, required: true }, // user.sessionVersion this token was minted under
    revoked: { type: Boolean, default: false }, // true = consumed by rotation OR revoked by logout
    userAgent: { type: String, default: '' },
    ip: { type: String, default: '' },
    expiresAt: { type: Date, required: true },
  },
  { timestamps: true }
);

// Mongo TTL index: auto-purge expired token records
refreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('RefreshToken', refreshTokenSchema);

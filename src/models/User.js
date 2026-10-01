const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const ROLES = ['guest', 'user', 'admin'];

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^\S+@\S+\.\S+$/, 'Invalid email format'],
    },
    passwordHash: {
      type: String,
      required: true,
      select: false, // never returned by default
    },
    role: {
      type: String,
      enum: ROLES,
      default: 'user',
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    failedLoginAttempts: {
      type: Number,
      default: 0,
    },
    lockUntil: {
      type: Date,
      default: null,
    },
    lastLoginAt: {
      type: Date,
      default: null,
    },
    twoFactorEnabled: {
      type: Boolean,
      default: false,
    },
    // Incremented on global logout. Every token carries the value it was minted
    // under; a mismatch means the token predates the logout. Server-controlled only.
    sessionVersion: {
      type: Number,
      default: 0,
    },
    // Last TOTP time step accepted for this user; codes for steps <= this are rejected (replay).
    twoFactorLastStep: {
      type: Number,
      default: 0,
    },
    twoFactorSecret: {
      type: String,
      default: null,
      select: false, // never returned by default; it's a TOTP seed
    },
  },
  { timestamps: true }
);

userSchema.methods.comparePassword = function comparePassword(candidate) {
  return bcrypt.compare(candidate, this.passwordHash);
};

userSchema.methods.isLocked = function isLocked() {
  return Boolean(this.lockUntil && this.lockUntil > Date.now());
};

userSchema.statics.hashPassword = async function hashPassword(plain) {
  const salt = await bcrypt.genSalt(12);
  return bcrypt.hash(plain, salt);
};

userSchema.set('toJSON', {
  transform: (_doc, ret) => {
    delete ret.passwordHash;
    delete ret.twoFactorSecret;
    delete ret.twoFactorLastStep;
    delete ret.sessionVersion;
    delete ret.failedLoginAttempts;
    delete ret.lockUntil;
    delete ret.__v;
    return ret;
  },
});

module.exports = mongoose.model('User', userSchema);
module.exports.ROLES = ROLES;

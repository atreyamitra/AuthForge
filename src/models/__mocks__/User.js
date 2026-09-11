/**
 * Manual Jest mock for the User model.
 *
 * WHY THIS EXISTS: the sandbox this was authored in cannot reach
 * fastdl.mongodb.org, so `mongodb-memory-server` can't download a real
 * mongod binary here. Rather than skip testing the persistence-adjacent
 * logic entirely, this in-memory double implements the exact subset of
 * the Mongoose API the controllers/middleware actually call, so the real
 * business logic (bcrypt hashing, lockout counting, RBAC role checks,
 * token issuance) is still exercised end-to-end by the test suite.
 *
 * On a machine that CAN reach mongodb.org (or against the Dockerized
 * mongo in docker-compose.yml), the real src/models/User.js is used
 * unmodified — this file only takes effect when a test calls
 * `jest.mock('../../src/models/User')`.
 */
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const ROLES = ['guest', 'user', 'admin'];

let store = new Map(); // _id -> record

function makeId() {
  return crypto.randomBytes(12).toString('hex');
}

function attachInstanceMethods(doc) {
  doc.comparePassword = function comparePassword(candidate) {
    return bcrypt.compare(candidate, doc.passwordHash);
  };
  doc.isLocked = function isLocked() {
    return Boolean(doc.lockUntil && doc.lockUntil > Date.now());
  };
  doc.save = async function save() {
    doc.updatedAt = new Date();
    store.set(doc._id, doc);
    return doc;
  };
  doc.toJSON = function toJSON() {
    const { passwordHash, twoFactorSecret, ...rest } = doc;
    return rest;
  };
  return doc;
}

function thenable(getResult) {
  return {
    select() {
      return this; // no-op: passwordHash is always present on the in-memory doc
    },
    limit(n) {
      this._limit = n;
      return this;
    },
    then(resolve, reject) {
      return Promise.resolve(getResult(this._limit)).then(resolve, reject);
    },
    catch(reject) {
      return Promise.resolve(getResult(this._limit)).catch(reject);
    },
  };
}

class User {
  static async create(data) {
    const existing = [...store.values()].find((u) => u.email === data.email.toLowerCase());
    if (existing) {
      const err = new Error('E11000 duplicate key error');
      err.code = 11000;
      err.keyValue = { email: data.email };
      throw err;
    }
    const now = new Date();
    const doc = {
      _id: makeId(),
      email: data.email.toLowerCase(),
      passwordHash: data.passwordHash,
      role: data.role && ROLES.includes(data.role) ? data.role : 'user',
      isActive: true,
      tokenVersion: data.tokenVersion ?? 0,
      failedLoginAttempts: 0,
      lockUntil: null,
      lastLoginAt: null,
      twoFactorEnabled: false,
      twoFactorSecret: null,
      createdAt: now,
      updatedAt: now,
    };
    attachInstanceMethods(doc);
    store.set(doc._id, doc);
    return doc;
  }

  static findOne(query) {
    return thenable(() => {
      const found = [...store.values()].find((u) =>
        Object.entries(query).every(([k, v]) => u[k] === v)
      );
      return found ? attachInstanceMethods({ ...found }) : null;
    });
  }

  static findById(id) {
    return thenable(() => {
      const found = store.get(id);
      return found ? attachInstanceMethods({ ...found }) : null;
    });
  }

  static find() {
    return thenable((limit) => {
      const all = [...store.values()].map((u) => attachInstanceMethods({ ...u }));
      return typeof limit === 'number' ? all.slice(0, limit) : all;
    });
  }

  static async findByIdAndUpdate(id, update, opts = {}) {
    const existing = store.get(id);
    if (!existing) return null;
    const updated = { ...existing, ...(update.$set || (update.$inc ? {} : update)), updatedAt: new Date() };
    for (const [key, amount] of Object.entries(update.$inc || {})) {
      updated[key] = (existing[key] || 0) + amount;
    }
    store.set(id, updated);
    attachInstanceMethods(updated);
    return opts.new === false ? attachInstanceMethods({ ...existing }) : updated;
  }

  static async hashPassword(plain) {
    const salt = await bcrypt.genSalt(10); // lower cost factor in tests for speed
    return bcrypt.hash(plain, salt);
  }

  static __reset() {
    store = new Map();
  }
}

module.exports = User;
module.exports.ROLES = ROLES;

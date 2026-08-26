/** Manual Jest mock for RefreshToken — see User mock for the full rationale. */
const crypto = require('crypto');

let store = new Map(); // _id -> record

function makeId() {
  return crypto.randomBytes(12).toString('hex');
}

function attachInstanceMethods(doc) {
  doc.save = async function save() {
    store.set(doc._id, doc);
    return doc;
  };
  return doc;
}

function thenable(getResult) {
  return {
    then(resolve, reject) {
      return Promise.resolve(getResult()).then(resolve, reject);
    },
    catch(reject) {
      return Promise.resolve(getResult()).catch(reject);
    },
  };
}

class RefreshToken {
  static async create(data) {
    const now = new Date();
    const doc = {
      _id: makeId(),
      user: data.user,
      tokenId: data.tokenId,
      revoked: false,
      userAgent: data.userAgent || '',
      ip: data.ip || '',
      expiresAt: data.expiresAt,
      createdAt: now,
      updatedAt: now,
    };
    attachInstanceMethods(doc);
    store.set(doc._id, doc);
    return doc;
  }

  static findOne(query) {
    return thenable(() => {
      const found = [...store.values()].find((t) =>
        Object.entries(query).every(([k, v]) => String(t[k]) === String(v))
      );
      return found ? attachInstanceMethods({ ...found }) : null;
    });
  }

  static async updateOne(query, update) {
    const found = [...store.values()].find((t) =>
      Object.entries(query).every(([k, v]) => String(t[k]) === String(v))
    );
    if (found) {
      Object.assign(found, update, { updatedAt: new Date() });
      store.set(found._id, found);
    }
    return { matchedCount: found ? 1 : 0 };
  }

  static async updateMany(query, update) {
    const matches = [...store.values()].filter((t) =>
      Object.entries(query).every(([k, v]) => String(t[k]) === String(v))
    );
    matches.forEach((t) => {
      Object.assign(t, update, { updatedAt: new Date() });
      store.set(t._id, t);
    });
    return { matchedCount: matches.length };
  }

  static __reset() {
    store = new Map();
  }
}

module.exports = RefreshToken;

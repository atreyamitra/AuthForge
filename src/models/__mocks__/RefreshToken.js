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

function matches(doc, query) {
  return Object.entries(query).every(([key, value]) => {
    if (value && typeof value === 'object' && '$gt' in value) return doc[key] > value.$gt;
    if (value && typeof value === 'object' && '$lt' in value) return doc[key] < value.$lt;
    return String(doc[key]) === String(value);
  });
}

class RefreshToken {
  static async findOneAndUpdate(query, update) {
    const found = [...store.values()].find(t => matches(t, query));
    if (!found) return null;
    Object.assign(found, update.$set || update);
    return attachInstanceMethods({ ...found });
  }

  static async create(data) {
    const now = new Date();
    const doc = {
      _id: makeId(),
      user: data.user,
      tokenId: data.tokenId,
      tokenVersion: data.tokenVersion,
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
        matches(t, query)
      );
      return found ? attachInstanceMethods({ ...found }) : null;
    });
  }

  static async updateOne(query, update) {
    const found = [...store.values()].find((t) =>
      matches(t, query)
    );
    if (found) {
      Object.assign(found, update.$set || update, { updatedAt: new Date() });
      store.set(found._id, found);
    }
    return { matchedCount: found ? 1 : 0 };
  }

  static async updateMany(query, update) {
    const matchingRecords = [...store.values()].filter((t) =>
      matches(t, query)
    );
    matchingRecords.forEach((t) => {
      Object.assign(t, update.$set || update, { updatedAt: new Date() });
      store.set(t._id, t);
    });
    return { matchedCount: matchingRecords.length };
  }

  static __reset() {
    store = new Map();
  }
}

module.exports = RefreshToken;

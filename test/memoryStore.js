const mongoose = require("mongoose");
const {
  Upload,
  Workspace,
  AbuseReport,
  AdminAuditLog,
  DailyStats,
} = require("../models");

function matchesCondition(val, cond) {
  if (cond && typeof cond === "object" && !Array.isArray(cond) && !(cond instanceof Date)) {
    if ("$in" in cond) {
      return cond.$in.some((item) => {
        if (item === null && (val === null || val === undefined)) return true;
        return item === val;
      });
    }
    if ("$exists" in cond) {
      return cond.$exists ? val !== undefined : val === undefined;
    }
    if ("$gte" in cond || "$lte" in cond || "$lt" in cond || "$gt" in cond) {
      const vTime = val instanceof Date ? val.getTime() : new Date(val).getTime();
      if (isNaN(vTime)) return false;
      if (cond.$gte !== undefined && vTime < new Date(cond.$gte).getTime()) return false;
      if (cond.$gt !== undefined && vTime <= new Date(cond.$gt).getTime()) return false;
      if (cond.$lte !== undefined && vTime > new Date(cond.$lte).getTime()) return false;
      if (cond.$lt !== undefined && vTime >= new Date(cond.$lt).getTime()) return false;
      return true;
    }
  }
  if (cond instanceof Date || val instanceof Date) {
    return new Date(val).getTime() === new Date(cond).getTime();
  }
  return String(val ?? "") === String(cond ?? "");
}

function matchesQuery(doc, query = {}) {
  if (!query || Object.keys(query).length === 0) return true;
  for (const [key, cond] of Object.entries(query)) {
    if (key === "$or" && Array.isArray(cond)) {
      if (!cond.some((sub) => matchesQuery(doc, sub))) return false;
      continue;
    }
    const val = key.includes(".")
      ? key.split(".").reduce((o, k) => (o ? o[k] : undefined), doc)
      : doc[key];
    if (!matchesCondition(val, cond)) return false;
  }
  return true;
}

function createQueryChain(items, isSingle = false) {
  let result = [...items];
  const chain = {
    sort(sortSpec = {}) {
      const entries = Object.entries(sortSpec);
      result.sort((a, b) => {
        for (const [field, dir] of entries) {
          const av = a[field] instanceof Date ? a[field].getTime() : a[field];
          const bv = b[field] instanceof Date ? b[field].getTime() : b[field];
          if (av < bv) return dir === -1 ? 1 : -1;
          if (av > bv) return dir === -1 ? -1 : 1;
        }
        return 0;
      });
      return chain;
    },
    limit(n) {
      result = result.slice(0, n);
      return chain;
    },
    select() {
      return chain;
    },
    lean() {
      return Promise.resolve(
        isSingle
          ? result[0]
            ? JSON.parse(JSON.stringify(result[0]))
            : null
          : JSON.parse(JSON.stringify(result))
      );
    },
    then(resolve, reject) {
      return Promise.resolve(isSingle ? result[0] || null : result).then(resolve, reject);
    },
  };
  return chain;
}

function attachInMemoryStore() {
  const stores = {
    Upload: [],
    Workspace: [],
    AbuseReport: [],
    AdminAuditLog: [],
    DailyStats: [],
  };

  function bindModel(Model, storeKey) {
    const list = stores[storeKey];

    Model.prototype.save = async function () {
      if (!this._id) {
        this._id = new mongoose.Types.ObjectId();
      }
      const idx = list.findIndex((item) => String(item._id) === String(this._id));
      if (idx === -1) {
        list.push(this);
      } else {
        list[idx] = this;
      }
      return this;
    };

    Model.create = async function (data) {
      const doc = new Model(data);
      await doc.save();
      return doc;
    };

    Model.find = function (query = {}) {
      const matched = list.filter((doc) => matchesQuery(doc, query));
      return createQueryChain(matched, false);
    };

    Model.findOne = function (query = {}) {
      const matched = list.filter((doc) => matchesQuery(doc, query));
      return createQueryChain(matched, true);
    };

    Model.findById = async function (id) {
      return list.find((doc) => String(doc._id) === String(id)) || null;
    };

    Model.findOneAndDelete = async function (query = {}) {
      const idx = list.findIndex((doc) => matchesQuery(doc, query));
      if (idx === -1) return null;
      const [removed] = list.splice(idx, 1);
      return removed;
    };

    Model.deleteOne = async function (query = {}) {
      const idx = list.findIndex((doc) => matchesQuery(doc, query));
      if (idx !== -1) list.splice(idx, 1);
      return { deletedCount: idx !== -1 ? 1 : 0 };
    };

    Model.deleteMany = async function (query = {}) {
      let deletedCount = 0;
      for (let i = list.length - 1; i >= 0; i--) {
        if (matchesQuery(list[i], query)) {
          list.splice(i, 1);
          deletedCount += 1;
        }
      }
      return { deletedCount };
    };

    Model.countDocuments = async function (query = {}) {
      return list.filter((doc) => matchesQuery(doc, query)).length;
    };

    Model.findOneAndUpdate = async function (query = {}, update = {}, opts = {}) {
      let doc = list.find((item) => matchesQuery(item, query));
      if (!doc && opts.upsert) {
        doc = new Model(query);
        await doc.save();
      }
      if (!doc) return null;
      if (update.$inc) {
        for (const [k, v] of Object.entries(update.$inc)) {
          doc[k] = (Number(doc[k]) || 0) + Number(v);
        }
      }
      if (update.$set) {
        for (const [k, v] of Object.entries(update.$set)) {
          doc[k] = v;
        }
      }
      await doc.save();
      return doc;
    };
  }

  bindModel(Upload, "Upload");
  bindModel(Workspace, "Workspace");
  bindModel(AbuseReport, "AbuseReport");
  bindModel(AdminAuditLog, "AdminAuditLog");
  bindModel(DailyStats, "DailyStats");

  return {
    stores,
    clearAll() {
      for (const k of Object.keys(stores)) {
        stores[k].length = 0;
      }
    },
  };
}

module.exports = { attachInMemoryStore };


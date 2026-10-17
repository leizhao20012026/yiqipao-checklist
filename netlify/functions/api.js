const crypto = require("crypto");
const { connectLambda, getStore } = require("@netlify/blobs");

const ADMIN_NAME = "admin";

const defaultCategories = [
    {
        name: "穿戴衣物",
        items: [
            { name: "速干半袖（跑团团服） - 不要使用棉线材质半袖", checked: false },
            { name: "运动短裤 - 速干短裤、或者防磨短裤", checked: false },
            { name: "跑步袜", checked: false },
            { name: "跑鞋 - 不要用新鞋、系双重鞋带，防止松脱", checked: false },
            { name: "遮阳帽 - 遮阳、吸汗", checked: false },
            { name: "一次性雨衣 – 到达起跑处开始穿用于防冻，开始起跑后丢在马路边", checked: false },
            { name: "Sports Bra（女生）", checked: false },
            { name: "头绳（女生）", checked: false }
        ]
    },
    {
        name: "穿戴物品",
        items: [
            { name: "太阳镜", checked: false },
            { name: "运动手表 - 提前充电，记录心率、配速及成绩", checked: false },
            { name: "护腕 - 擦汗", checked: false },
            { name: "腰包、跑步背心 - 用于放手机、能量棒、盐丸等", checked: false },
            { name: "存包袋以及存包卡（在组委会的发放的物资包中，若不存包，可以不带）", checked: false }
        ]
    },
    {
        name: "涂抹及食品",
        items: [
            { name: "防晒霜", checked: false },
            { name: "凡士林 - 腋下、乳头、裆部、脚步易磨部位（容易出血 - 全马必须）", checked: false },
            { name: "肌肉贴 - 可选", checked: false },
            { name: "能量胶 – 跑前及10公里处吃", checked: false },
            { name: "盐丸 – 10公里处吃", checked: false }
        ]
    },
    {
        name: "重要物品",
        items: [
            { name: "号码簿 - 提前固定在运动衣上", checked: false },
            { name: "手机 - 提前充好电", checked: false },
            { name: "充电宝 - 若需要", checked: false }
        ]
    }
];

function json(status, body) {
    return {
        statusCode: status,
        headers: { "Content-Type": "application/json; charset=utf-8" },
        body: JSON.stringify(body)
    };
}

function secret() {
    return process.env.AUTH_SECRET || "";
}

function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString("hex");
    const hash = crypto.scryptSync(password, salt, 32).toString("hex");
    return `scrypt$${salt}$${hash}`;
}

function legacyHash(password) {
    const text = `running-checklist:${password}`;
    let hash = 2166136261;
    for (let i = 0; i < text.length; i += 1) {
        hash ^= text.charCodeAt(i);
        hash = Math.imul(hash, 16777619);
    }
    return `local-${(hash >>> 0).toString(16)}-${text.length}`;
}

function verifyPassword(password, stored) {
    if (!stored || !password) return false;
    if (stored.startsWith("local-")) return legacyHash(password) === stored;
    const [scheme, salt, hash] = stored.split("$");
    if (scheme !== "scrypt" || !salt || !hash) return false;
    const check = crypto.scryptSync(password, salt, 32).toString("hex");
    if (check.length !== hash.length) return false;
    return crypto.timingSafeEqual(Buffer.from(check, "hex"), Buffer.from(hash, "hex"));
}

function signToken(username) {
    const body = Buffer.from(JSON.stringify({
        username,
        exp: Date.now() + 30 * 24 * 60 * 60 * 1000
    })).toString("base64url");
    const sig = crypto.createHmac("sha256", secret()).update(body).digest("base64url");
    return `${body}.${sig}`;
}

function readToken(event) {
    const header = event.headers.authorization || event.headers.Authorization || "";
    const token = header.replace(/^Bearer\s+/i, "");
    if (!token || !secret()) return null;
    const [body, sig] = token.split(".");
    if (!body || !sig) return null;
    const expected = crypto.createHmac("sha256", secret()).update(body).digest("base64url");
    const a = Buffer.from(sig);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    try {
        const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
        if (!payload.username || payload.exp < Date.now()) return null;
        return payload.username;
    } catch (error) {
        return null;
    }
}

function routeOf(event) {
    const path = event.path || "";
    const apiAt = path.indexOf("/api/");
    if (apiAt >= 0) return path.slice(apiAt + 4);
    return "/";
}

function readBody(event) {
    if (!event.body) return {};
    try {
        return JSON.parse(event.body);
    } catch (error) {
        return {};
    }
}

function publicUser(name, account) {
    return {
        username: name,
        role: account.role === "admin" ? "admin" : "user"
    };
}

async function loadDb(store) {
    const data = await store.get("database", { type: "json" });
    if (data && data.users) return data;
    return {
        users: {
            [ADMIN_NAME]: {
                passwordHash: hashPassword("monkey"),
                role: "admin",
                categories: []
            }
        }
    };
}

exports.handler = async (event) => {
    if (!secret()) return json(500, { error: "服务器还没有配置密钥" });
    try {
        if (event.blobs) connectLambda(event);
    } catch (error) {
        return json(500, { error: "存储连接失败" });
    }

    let store;
    try {
        store = getStore("checklist");
    } catch (error) {
        return json(500, { error: "存储暂时不可用" });
    }
    const db = await loadDb(store);
    const route = routeOf(event);
    const method = event.httpMethod;
    const body = readBody(event);
    let changed = !await store.get("database");

    const save = async () => {
        await store.setJSON("database", db);
        changed = false;
    };

    if (changed) await save();

    if (method === "GET" && route === "/users") {
        return json(200, {
            users: Object.keys(db.users).map((name) => publicUser(name, db.users[name]))
        });
    }

    if (method === "POST" && route === "/register") {
        const username = String(body.username || "").trim();
        const password = String(body.password || "");
        if (!username || !password) return json(400, { error: "请填写用户名和密码" });
        if (username === ADMIN_NAME || db.users[username]) return json(400, { error: "用户名已存在" });
        if (username.length > 40) return json(400, { error: "用户名太长" });
        db.users[username] = {
            passwordHash: hashPassword(password),
            role: "user",
            categories: JSON.parse(JSON.stringify(defaultCategories))
        };
        await save();
        return json(200, {
            token: signToken(username),
            user: publicUser(username, db.users[username]),
            categories: db.users[username].categories
        });
    }

    if (method === "POST" && route === "/login") {
        const username = String(body.username || "").trim();
        const password = String(body.password || "");
        const account = db.users[username];
        if (!account || !verifyPassword(password, account.passwordHash)) {
            return json(401, { error: "用户名或密码不正确" });
        }
        if (account.passwordHash.startsWith("local-")) {
            account.passwordHash = hashPassword(password);
            await save();
        }
        return json(200, {
            token: signToken(username),
            user: publicUser(username, account),
            categories: account.categories || []
        });
    }

    if (method === "POST" && route === "/delete-account") {
        const username = String(body.username || "").trim();
        const password = String(body.password || "");
        if (username === ADMIN_NAME) return json(400, { error: "不能删除超级用户" });
        const account = db.users[username];
        if (!account || !verifyPassword(password, account.passwordHash)) {
            return json(401, { error: "密码不正确" });
        }
        delete db.users[username];
        await save();
        return json(200, { ok: true });
    }

    if (method === "POST" && route === "/migrate") {
        const incoming = body.users && typeof body.users === "object" ? body.users : {};
        Object.keys(incoming).forEach((name) => {
            const account = incoming[name];
            if (!name || name === ADMIN_NAME || db.users[name] || !account) return;
            if (!account.passwordHash || typeof account.passwordHash !== "string") return;
            db.users[name] = {
                passwordHash: account.passwordHash,
                role: "user",
                categories: Array.isArray(account.categories) ? account.categories : JSON.parse(JSON.stringify(defaultCategories))
            };
        });
        await save();
        return json(200, {
            users: Object.keys(db.users).map((name) => publicUser(name, db.users[name]))
        });
    }

    const username = readToken(event);
    const account = username && db.users[username];
    if (!account) return json(401, { error: "请先登录" });

    if (method === "PUT" && route === "/me") {
        if (account.role === "admin") return json(400, { error: "超级用户没有清单" });
        if (!Array.isArray(body.categories)) return json(400, { error: "清单格式不正确" });
        account.categories = body.categories;
        await save();
        return json(200, { ok: true });
    }

    if (account.role !== "admin") return json(403, { error: "没有权限" });

    if (method === "PATCH" && route === "/users") {
        const oldName = String(body.oldName || "").trim();
        const newName = String(body.newName || "").trim();
        const newPassword = String(body.newPassword || "");
        if (!oldName || oldName === ADMIN_NAME || !db.users[oldName]) return json(400, { error: "找不到这个用户" });
        if (!newName) return json(400, { error: "请填写用户名" });
        if (newName !== oldName && (newName === ADMIN_NAME || db.users[newName])) {
            return json(400, { error: "用户名已存在" });
        }
        const target = db.users[oldName];
        if (newPassword) target.passwordHash = hashPassword(newPassword);
        if (newName !== oldName) {
            db.users[newName] = target;
            delete db.users[oldName];
        }
        await save();
        return json(200, { ok: true });
    }

    if (method === "DELETE" && route === "/users") {
        const targetName = String(body.username || "").trim();
        if (!targetName || targetName === ADMIN_NAME || !db.users[targetName]) {
            return json(400, { error: "不能删除这个用户" });
        }
        delete db.users[targetName];
        await save();
        return json(200, { ok: true });
    }

    return json(404, { error: "没有这个接口" });
};

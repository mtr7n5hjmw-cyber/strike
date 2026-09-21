import "dotenv/config";
import http from "node:http";
import crypto from "node:crypto";
import { fork } from "node:child_process";
import { readFile } from "node:fs/promises";
import { URL } from "node:url";

const port = Number(process.env.PORT || 3000);
const frontendOrigin = process.env.FRONTEND_ORIGIN || `http://localhost:${port}`;
const allowedOrigins = new Set([
    frontendOrigin,
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "null"
]);
const sessionSecret = process.env.SESSION_SECRET;
const helperSharedToken = process.env.HELPER_SHARED_TOKEN || "";
const sessions = new Map();
const hwidChecks = new Map();
const sessionLifetime = 8 * 60 * 60 * 1000;
const hwidCheckLifetime = 2 * 60 * 1000;

if (!sessionSecret || sessionSecret.length < 32) {
    throw new Error("SESSION_SECRET must be set to at least 32 characters.");
}

function sendJson(response, status, body, extraHeaders = {}) {
    response.writeHead(status, {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        ...extraHeaders
    });
    response.end(JSON.stringify(body));
}

function corsHeaders(request) {
    const origin = request.headers.origin;
    const forwardedProtocol = request.headers["x-forwarded-proto"] || "http";
    const requestOrigin = `${forwardedProtocol}://${request.headers.host}`;
    const isSameOrigin = origin && origin === requestOrigin;
    if (origin && !allowedOrigins.has(origin) && !isSameOrigin) {
        return null;
    }

    return {
        "Access-Control-Allow-Origin": origin || frontendOrigin,
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
    };
}

function parseCookies(request) {
    return Object.fromEntries((request.headers.cookie || "").split(";").filter(Boolean).map(item => {
        const separator = item.indexOf("=");
        return [item.slice(0, separator).trim(), decodeURIComponent(item.slice(separator + 1).trim())];
    }));
}

function sign(value) {
    return crypto.createHmac("sha256", sessionSecret).update(value).digest("base64url");
}

function createSession(worker) {
    const id = crypto.randomBytes(32).toString("base64url");
    sessions.set(id, { worker, createdAt: Date.now() });
    return `${id}.${sign(id)}`;
}

function getSession(request) {
    const value = parseCookies(request).sm_session || "";
    const separator = value.lastIndexOf(".");
    if (separator < 1) return null;

    const id = value.slice(0, separator);
    const signature = value.slice(separator + 1);
    const expected = sign(id);
    if (signature.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
        return null;
    }

    const session = sessions.get(id);
    if (!session) return null;
    if (Date.now() - session.createdAt > sessionLifetime) {
        clearSession({ id, ...session });
        return null;
    }

    return { id, ...session };
}

function sessionCookie(value, maxAge = 60 * 60 * 24) {
    const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
    return `sm_session=${encodeURIComponent(value)}; Max-Age=${maxAge}; Path=/; HttpOnly; SameSite=Lax${secure}`;
}

function clearSession(session) {
    if (!session) return;
    sessions.delete(session.id);
    session.worker.kill();
}

function readBody(request) {
    return new Promise((resolve, reject) => {
        let body = "";
        request.on("data", chunk => {
            body += chunk;
            if (body.length > 32 * 1024) {
                reject(new Error("Request body is too large."));
                request.destroy();
            }
        });
        request.on("end", () => {
            try {
                resolve(body ? JSON.parse(body) : {});
            } catch {
                reject(new Error("Request body must be valid JSON."));
            }
        });
        request.on("error", reject);
    });
}

function validateString(value, field, maxLength = 128) {
    if (typeof value !== "string" || value.trim().length === 0 || value.length > maxLength) {
        throw new Error(`${field} is required.`);
    }
    return value.trim();
}

function secureEquals(left, right) {
    const leftBuffer = Buffer.from(left || "");
    const rightBuffer = Buffer.from(right || "");
    return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function cleanupHwidChecks() {
    const now = Date.now();
    for (const [challenge, check] of hwidChecks) {
        if (check.expiresAt <= now) hwidChecks.delete(challenge);
    }
}

function createHwidChallenge(data) {
    cleanupHwidChecks();
    const challenge = crypto.randomBytes(32).toString("base64url");
    hwidChecks.set(challenge, {
        ...data,
        challenge,
        expiresAt: Date.now() + hwidCheckLifetime,
        status: "PENDING"
    });
    return { challenge, expiresAt: hwidChecks.get(challenge).expiresAt };
}

function compareHwid(expected, actual) {
    if (!expected || expected === "N/A" || expected === "Unavailable") return "NO_HWID_REGISTERED";
    return secureEquals(String(expected).trim().toLowerCase(), String(actual).trim().toLowerCase())
        ? "HWID_MATCH"
        : "HWID_DOES_NOT_MATCH";
}

function startWorker() {
    const worker = fork(new URL("./backend/keyauth-worker.js", import.meta.url), [], {
        stdio: ["ignore", "pipe", "pipe", "ipc"]
    });
    worker.keyauthOutput = "";
    worker.stdout.on("data", chunk => {
        worker.keyauthOutput += chunk.toString();
        process.stdout.write(chunk);
    });
    worker.stderr.on("data", chunk => {
        worker.keyauthOutput += chunk.toString();
        process.stderr.write(chunk);
    });
    return worker;
}

function workerRequest(worker, message, timeout = 15000) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            cleanup();
            reject(new Error("KeyAuth request timed out."));
        }, timeout);

        const onMessage = result => {
            cleanup();
            if (result.ok) resolve(result);
            else reject(new Error(result.error || "KeyAuth request failed."));
        };

        const onExit = () => {
            cleanup();
            const output = worker.keyauthOutput.trim();
            const message = output.split(/\r?\n/).filter(Boolean).pop();
            reject(new Error(message || "KeyAuth worker ended before completing the request."));
        };

        function cleanup() {
            clearTimeout(timer);
            worker.off("message", onMessage);
            worker.off("exit", onExit);
        }

        worker.once("message", onMessage);
        worker.once("exit", onExit);

        if (!worker.connected) {
            cleanup();
            reject(new Error("KeyAuth worker is no longer available."));
            return;
        }

        worker.send(message, sendError => {
            if (sendError) {
                cleanup();
                reject(new Error("KeyAuth worker is no longer available."));
            }
        });
    });
}

function classifyLoginError(error) {
    const raw = String(error?.message || "");
    const message = raw.toLowerCase();

    if (message.includes("hwid") || message.includes("hardware") || message.includes("device")) {
        return { status: 401, error: "HWID Mismatch: This account is linked to a different device." };
    }
    if (message.includes("password") || message.includes("username") || message.includes("credential")) {
        return { status: 401, error: "Invalid credentials. Check your username and password." };
    }
    if (message.includes("expired") || message.includes("subscription") || message.includes("license")) {
        return { status: 403, error: "This account's subscription or license is expired or invalid." };
    }
    if (message.includes("suspend") || message.includes("banned") || message.includes("blacklist") || message.includes("blocked")) {
        return { status: 403, error: "This account is suspended or blocked." };
    }
    if (message.includes("timeout") || message.includes("network") || message.includes("worker") || message.includes("fetch")) {
        return { status: 503, error: "KeyAuth is currently unavailable. Please try again." };
    }
    return { status: 401, error: "Authentication failed. Please try again." };
}

function publicUser(user) {
    if (!user) return null;
    return {
        username: user.username || "Unavailable",
        ip: user.ip || "Unavailable",
        hwid: user.hwid || "Unavailable",
        expires: user.expires || null,
        createdate: user.createdate || null,
        lastlogin: user.lastlogin || null,
        subscriptions: Array.isArray(user.subscriptions) ? user.subscriptions.map(subscription => ({
            subscription: subscription.subscription || "Unavailable",
            expiry: subscription.expiry || null,
            timeleft: subscription.timeleft || null,
            key: subscription.key || null
        })) : []
    };
}

async function authenticated(request, response) {
    const session = getSession(request);
    if (!session) {
        sendJson(response, 401, { error: "Not authenticated." });
        return null;
    }

    try {
        const result = await workerRequest(session.worker, { type: "check" });
        if (!result.valid) {
            clearSession(session);
            sendJson(response, 401, { error: "KeyAuth session is no longer valid." });
            return null;
        }
        return { session, user: publicUser(result.user) };
    } catch (error) {
        clearSession(session);
        sendJson(response, 401, { error: error.message });
        return null;
    }
}

async function handle(request, response) {
    const headers = corsHeaders(request);
    if (!headers) {
        sendJson(response, 403, { error: "Origin is not allowed." });
        return;
    }
    Object.assign(response, { _corsHeaders: headers });

    if (request.method === "OPTIONS") {
        response.writeHead(204, headers);
        response.end();
        return;
    }

    const url = new URL(request.url, `http://${request.headers.host}`);
    const json = body => sendJson(response, 200, body, headers);

    try {
        if (request.method === "GET" && url.pathname === "/health") {
            sendJson(response, 200, { status: "ok" }, headers);
            return;
        }

        if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
            const html = await readFile(new URL("./index.html", import.meta.url), "utf8");
            response.writeHead(200, {
                ...headers,
                "Content-Type": "text/html; charset=utf-8",
                "Cache-Control": "no-store"
            });
            response.end(html);
            return;
        }

        if (request.method === "GET" && url.pathname === "/Screenshot_2026-08-18_012012.png") {
            const image = await readFile(new URL("./Screenshot_2026-08-18_012012.png", import.meta.url));
            response.writeHead(200, {
                ...headers,
                "Content-Type": "image/png",
                "Cache-Control": "no-store"
            });
            response.end(image);
            return;
        }

        if (request.method === "GET" && url.pathname === "/strikemenu-favicon.svg") {
            const favicon = await readFile(new URL("./strikemenu-favicon.svg", import.meta.url), "utf8");
            response.writeHead(200, {
                ...headers,
                "Content-Type": "image/svg+xml",
                "Cache-Control": "no-store"
            });
            response.end(favicon);
            return;
        }

        if (request.method === "POST" && url.pathname === "/api/auth/login/start") {
            const body = await readBody(request);
            const username = validateString(body.username, "Username");
            const password = validateString(body.password, "Password", 512);
            if (!helperSharedToken) {
                sendJson(response, 503, { error: "The Windows helper is not configured." }, headers);
                return;
            }
            json(createHwidChallenge({ kind: "login", username, password }));
            return;
        }

        if (request.method === "POST" && url.pathname === "/api/auth/login") {
            const body = await readBody(request);
            const username = validateString(body.username, "Username");
            const password = validateString(body.password, "Password", 512);
            const worker = startWorker();
            try {
                await workerRequest(worker, { type: "init" });
                const result = await workerRequest(worker, { type: "login", username, password });
                const cookie = createSession(worker);
                sendJson(response, 200, { authenticated: true, user: publicUser(result.user) }, {
                    ...headers,
                    "Set-Cookie": sessionCookie(cookie)
                });
            } catch (error) {
                if (worker.connected) worker.kill();
                const classified = classifyLoginError(error);
                sendJson(response, classified.status, { error: classified.error }, headers);
            }
            return;
        }

        if (request.method === "POST" && url.pathname === "/api/auth/register") {
            const body = await readBody(request);
            const username = validateString(body.username, "Username");
            const password = validateString(body.password, "Password", 512);
            const license = validateString(body.license, "License key");
            const hwid = body.hwid ? validateString(body.hwid, "Device ID", 128) : undefined;
            const worker = startWorker();
            await workerRequest(worker, { type: "init" });
            const result = await workerRequest(worker, { type: "register", username, password, license, hwid });
            const cookie = createSession(worker);
            sendJson(response, 200, { authenticated: true, user: publicUser(result.user) }, {
                ...headers,
                "Set-Cookie": sessionCookie(cookie)
            });
            return;
        }

        if (request.method === "GET" && url.pathname === "/api/auth/session") {
            const authenticatedSession = await authenticated(request, response);
            if (!authenticatedSession) return;
            json({ authenticated: true, user: authenticatedSession.user });
            return;
        }

        if (request.method === "POST" && url.pathname === "/api/auth/logout") {
            const session = getSession(request);
            clearSession(session);
            sendJson(response, 200, { authenticated: false }, { ...headers, "Set-Cookie": sessionCookie("", 0) });
            return;
        }

        if (request.method === "GET" && url.pathname === "/api/account") {
            const authenticatedSession = await authenticated(request, response);
            if (!authenticatedSession) return;
            json({ user: authenticatedSession.user });
            return;
        }

        if (request.method === "POST" && url.pathname === "/api/hwid/check/start") {
            const authenticatedSession = await authenticated(request, response);
            if (!authenticatedSession) return;
            if (!helperSharedToken) {
                sendJson(response, 503, { error: "The Windows helper is not configured." }, headers);
                return;
            }

            const { challenge, expiresAt } = createHwidChallenge({
                sessionId: authenticatedSession.session.id,
                kind: "check"
            });
            json({ challenge, expiresAt });
            return;
        }

        if (request.method === "GET" && url.pathname === "/api/hwid/check/status") {
            cleanupHwidChecks();
            const challenge = url.searchParams.get("challenge") || "";
            const check = hwidChecks.get(challenge);
            if (!check) {
                sendJson(response, 404, { error: "HWID check was not found or has expired." }, headers);
                return;
            }

            if (check.kind === "check") {
                const authenticatedSession = await authenticated(request, response);
                if (!authenticatedSession || check.sessionId !== authenticatedSession.session.id) return;
            }

            const result = { status: check.status };
            if (check.status === "AUTHENTICATED") {
                result.authenticated = true;
                result.user = publicUser(check.user);
            }
            if (check.status === "ERROR") result.error = check.error;
            sendJson(response, 200, result, check.status === "AUTHENTICATED"
                ? { ...headers, "Set-Cookie": sessionCookie(check.cookie) }
                : headers);
            return;
        }

        if (request.method === "POST" && url.pathname === "/api/hwid/check/complete") {
            const body = await readBody(request);
            if (!helperSharedToken || !secureEquals(body.helperToken, helperSharedToken)) {
                sendJson(response, 403, { error: "Helper authentication failed." }, headers);
                return;
            }

            const challenge = validateString(body.challenge, "Challenge", 128);
            const hwid = validateString(body.hwid, "HWID", 256);
            cleanupHwidChecks();
            const check = hwidChecks.get(challenge);
            if (!check) {
                sendJson(response, 404, { error: "HWID check was not found or has expired." }, headers);
                return;
            }

            if (check.kind === "login") {
                const worker = startWorker();
                try {
                    await workerRequest(worker, { type: "init" });
                    const result = await workerRequest(worker, {
                        type: "login",
                        username: check.username,
                        password: check.password,
                        hwid
                    });
                    const cookie = createSession(worker);
                    check.status = "AUTHENTICATED";
                    check.user = result.user;
                    check.cookie = cookie;
                    check.expiresAt = Date.now() + hwidCheckLifetime;
                } catch (error) {
                    if (worker.connected) worker.kill();
                    const classified = classifyLoginError(error);
                    check.status = "ERROR";
                    check.error = classified.error;
                    check.expiresAt = Date.now() + hwidCheckLifetime;
                }
                json({ status: check.status });
                return;
            }

            const session = sessions.get(check.sessionId);
            if (!session) {
                sendJson(response, 401, { error: "The website session has expired." }, headers);
                return;
            }
            const result = await workerRequest(session.worker, { type: "check" });
            check.status = compareHwid(result.user?.hwid, hwid);
            check.expiresAt = Date.now() + hwidCheckLifetime;
            json({ status: check.status });
            return;
        }

        if (request.method === "POST" && url.pathname === "/api/license/redeem") {
            const authenticatedSession = await authenticated(request, response);
            if (!authenticatedSession) return;
            const body = await readBody(request);
            const license = validateString(body.license, "License key");
            await workerRequest(authenticatedSession.session.worker, {
                type: "upgrade",
                username: authenticatedSession.user.username,
                license
            }, 1000);
            sendJson(response, 502, {
                error: "License redemption could not be confirmed by the official SDK."
            }, headers);
            return;
        }

        sendJson(response, 404, { error: "Not found." }, headers);
    } catch (error) {
        sendJson(response, 400, { error: error instanceof Error ? error.message : "Request failed." }, headers);
    }
}

const server = http.createServer((request, response) => {
    handle(request, response).catch(error => {
        sendJson(response, 500, { error: error.message });
    });
});

server.listen(port, () => {
    console.log(`StrikeMenu backend listening on http://localhost:${port}`);
});

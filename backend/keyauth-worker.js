import KeyAuth from "./keyauth-sdk/keyauth.js";
import os from "node:os";
import { execFileSync } from "node:child_process";

const KeyAuthApp = new KeyAuth({
    name: "Robbiewright518's Application",
    ownerid: "rZE8DI0PZ8",
    version: "1.0"
});

function send(message) {
    if (process.connected) {
        process.send(message);
    }
}

function getSupportedHwid(requestedHwid) {
    if (typeof requestedHwid === "string" && requestedHwid.trim()) {
        return requestedHwid.trim();
    }

    if (os.platform() !== "win32") {
        return undefined;
    }

    const sid = execFileSync(
        "powershell.exe",
        [
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value"
        ],
        { encoding: "utf8", windowsHide: true }
    ).trim();

    if (!sid) {
        throw new Error("Unable to determine the Windows user SID for KeyAuth HWID.");
    }

    return sid;
}

async function handle(message) {
    if (message.type === "init") {
        await KeyAuthApp.init();
        send({ ok: true, type: "init" });
        return;
    }

    if (message.type === "login") {
        await KeyAuthApp.login(message.username, message.password, undefined, getSupportedHwid(message.hwid));
        send({ ok: true, type: "user", user: KeyAuthApp.user_data });
        return;
    }

    if (message.type === "register") {
        await KeyAuthApp.register(message.username, message.password, message.license, getSupportedHwid(message.hwid));
        send({ ok: true, type: "user", user: KeyAuthApp.user_data });
        return;
    }

    if (message.type === "check") {
        const valid = await KeyAuthApp.check();
        send({ ok: true, type: "check", valid, user: KeyAuthApp.user_data });
        return;
    }

    if (message.type === "account") {
        send({ ok: true, type: "user", user: KeyAuthApp.user_data });
        return;
    }

    if (message.type === "upgrade") {
        await KeyAuthApp.upgrade(message.username, message.license);
        send({ ok: true, type: "upgrade" });
    }
}

process.on("message", message => {
    handle(message).catch(error => {
        send({ ok: false, error: error instanceof Error ? error.message : "KeyAuth request failed." });
    });
});

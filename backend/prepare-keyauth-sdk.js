import { mkdir, writeFile } from "node:fs/promises";

const sdkUrl = "https://raw.githubusercontent.com/KeyAuth/KeyAuth-JavaScript-Example/main/javascript/src/keyauth.js";
const response = await fetch(sdkUrl);

if (!response.ok) {
    throw new Error(`Unable to download the official KeyAuth SDK: ${response.status}`);
}

await mkdir("backend/keyauth-sdk", { recursive: true });
await writeFile("backend/keyauth-sdk/keyauth.js", await response.text(), "utf8");
console.log("Downloaded the official KeyAuth JavaScript SDK source.");

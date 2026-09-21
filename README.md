# StrikeMenu Windows helper

`Hwid.cpp` is the shared HWID implementation. Link it into both `StrikeMenuHelper.exe` and the main `StrikeMenu.exe`; do not duplicate the algorithm.

The website login must be allowed to authenticate without enforcing a browser HWID. The helper check is the Windows-device verification step; a browser-generated identifier must not be used as the KeyAuth HWID.

Before compiling the helper, replace these constants in `StrikeMenuHelper.cpp`:

- `BACKEND_HOST`: the hostname only, without `https://`
- `ALLOWED_ORIGIN`: the complete website origin
- `HELPER_SHARED_TOKEN`: the same long random value configured as the backend `HELPER_SHARED_TOKEN`

The helper listens only on `127.0.0.1:37891`, accepts requests from the configured website origin, reads only the Windows `MachineGuid`, hashes it with SHA-256, and sends it to the backend over HTTPS. The raw HWID is never returned to the browser.

Build with Visual Studio Developer Command Prompt:

```text
cl /std:c++17 /EHsc /DUNICODE /D_UNICODE Hwid.cpp StrikeMenuHelper.cpp /Fe:StrikeMenuHelper.exe advapi32.lib bcrypt.lib winhttp.lib ws2_32.lib user32.lib
```

The backend must have `HELPER_SHARED_TOKEN` set. This initial helper uses a shared token plus a one-time backend challenge; production distribution should move the token into a signed installer/protected Windows storage and add helper registration if stronger anti-impersonation is required.
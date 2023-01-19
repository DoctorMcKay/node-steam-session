const { EAuthSessionGuardType, EAuthTokenPlatformType, LoginSession } = require("steam-session");
const { generateAuthCode } = require("steam-totp");
const fetch = require("node-fetch");

const config = {
    "accountName":  "username",
    "password":     "password",
    "sharedSecret": "shared secret",
};

async function loginToSteamPartner(session) {
    // We can also get web cookies now that we've negotiated a session
    let webCookies = await session.getWebCookies();
    console.log("Web session cookies:");
    console.log(webCookies);

    let body = await fetch("https://partner.steamgames.com/", {
        "headers": {
            "Cookie":                    webCookies.join("; "),
            "User-Agent":                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0",
            "Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language":           "en-US,en;q=0.5",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest":            "document",
            "Sec-Fetch-Mode":            "navigate",
            "Sec-Fetch-Site":            "same-origin",
            "Sec-Fetch-User":            "?1",
        },
    }).then((res) => res.text());

    console.log("Are we logged in?", body.includes("javascript:Logout()"));
}

(async() => {
    let { accountName, password, sharedSecret } = config;
    let session = new LoginSession(EAuthTokenPlatformType.WebBrowser);
    let startResult = await session.startWithCredentials({
        accountName,
        password,
    });

    if (startResult.actionRequired && startResult.validActions.includes(EAuthSessionGuardType.DeviceCode)) {
        let code = generateAuthCode(sharedSecret);
        await session.submitSteamGuardCode(code);
    } else if (startResult.actionRequired) {
        throw new Error("Login action is required, but we don't know how to handle it");
    }

    session.on("authenticated", async() => {
        console.log(`Successfully logged in as ${session.accountName}`);
        loginToSteamPartner(session);
    });

    session.on("timeout", () => {
        console.log("This login attempt has timed out.");
    });

    session.on("error", (err) => {
        // This should ordinarily not happen. This only happens in case there's some kind of unexpected error while
        // polling, e.g. the network connection goes down or Steam chokes on something.
        console.log(`ERROR: This login attempt has failed! ${err.message}`);
    });
})();

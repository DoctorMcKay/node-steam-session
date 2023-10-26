# Steam Session Manager

[![npm version](https://img.shields.io/npm/v/steam-session.svg)](https://npmjs.com/package/steam-session)
[![npm downloads](https://img.shields.io/npm/dm/steam-session.svg)](https://npmjs.com/package/steam-session)
[![license](https://img.shields.io/npm/l/steam-session.svg)](https://github.com/DoctorMcKay/node-steam-session/blob/master/LICENSE)
[![sponsors](https://img.shields.io/github/sponsors/DoctorMcKay.svg)](https://github.com/sponsors/DoctorMcKay)

This module enables you to negotiate Steam tokens by authenticating with the Steam login server. **This is for use with
your own accounts.** This is not to be used to authenticate other Steam users or to gain access to their accounts. For
that use-case, please use the [Steam OpenID service](https://steamcommunity.com/dev) (you may want to consider using
[steam-signin](https://www.npmjs.com/package/steam-signin)) and the many available [WebAPIs](https://steamapi.xpaw.me/).

Node.js v12.22.0 or later is required to use this module.

- [Concepts](#concepts)
- [Example Code](#example-code)
- [Exports](#exports)
	- [Enums](#enums)
		- [EAuthSessionSecurityHistory](#eauthsessionsecurityhistory)
        - [EAuthSessionGuardType](#eauthsessionguardtype)
        - [EAuthTokenPlatformType](#eauthtokenplatformtype)
        - [EResult](#eresult)
        - [ESessionPersistence](#esessionpersistence)
    - [Custom Transports](#custom-transports)
- [LoginSession](#loginsession)
	- [Properties](#properties)
		- [steamID](#steamid)
        - [loginTimeout](#logintimeout)
        - [accountName](#accountname)
        - [accessToken](#accesstoken)
        - [refreshToken](#refreshtoken)
        - [steamGuardMachineToken](#steamguardmachinetoken)
    - [Methods](#methods)
		- [Constructor(platformType\[, options\])](#constructorplatformtype-options)
        - [startWithCredentials(details)](#startwithcredentialsdetails)
        - [startWithQR()](#startwithqr)
        - [submitSteamGuardCode(authCode)](#submitsteamguardcodeauthcode)
        - [forcePoll()](#forcepoll)
        - [cancelLoginAttempt()](#cancelloginattempt)
        - [getWebCookies()](#getwebcookies)
        - [refreshAccessToken()](#refreshaccesstoken)
        - [renewRefreshToken()](#renewrefreshtoken)
    - [Events](#events)
		- [polling](#polling)
        - [timeout](#timeout)
        - [remoteInteraction](#remoteinteraction)
        - [steamGuardMachineToken](#steamguardmachinetoken-1)
        - [authenticated](#authenticated)
        - [error](#error)
- [LoginApprover](#loginapprover)
	- [Properties](#properties-1)
		- [steamID](#steamid-1)
        - [accessToken](#accesstoken-1)
        - [sharedSecret](#sharedsecret)
    - [Methods](#methods-1)
        - [Constructor(accessToken, sharedSecret\[, options\])](#constructoraccesstoken-sharedsecret-options)
        - [getAuthSessionInfo(qrChallengeUrl)](#getauthsessioninfoqrchallengeurl)
        - [approveAuthSession(details)](#approveauthsessiondetails)

# Concepts

Logging into Steam is a two-step process.

1. You start a login session either using your account credentials (username and password) or by generating a QR code
	- Use [`startWithCredentials`](#startwithcredentialsdetails) to start a login session using your account credentials
    - Use [`startWithQR`](#startwithqrdetails) to start a QR login session
2. Assuming any credentials you provided when you started the session were correct, Steam replies with a list of login guards
	- See [EAuthSessionGuardType](https://github.com/DoctorMcKay/node-steam-session/blob/master/src/enums-steam/EAuthSessionGuardType.ts)
	- If your account doesn't have Steam Guard enabled or you provided a valid code upfront, there may be 0 guards required
    - Only one guard must be satisfied to complete the login. For example, you might be given a choice of providing a TOTP code or confirming the login in your Steam mobile app
3. When you satisfy any guards, Steam sends back an access token and a refresh token. These can be used to:
    - [Log on with node-steam-user](https://github.com/DoctorMcKay/node-steam-user#logondetails)
    - [Obtain web session cookies](#getwebcookies)
    - Authenticate with WebAPI methods used by the mobile app

# Example Code

See the [examples directory on GitHub](https://github.com/DoctorMcKay/node-steam-session/tree/master/examples) for example code.

# Exports

When using CommonJS (`require()`), steam-session exports an object. When using ES6 modules (`import`), steam-session does
not offer a default export and you will need to import specific things.

The majority of steam-session consumers will only care about enums, and the [`LoginSession`](#loginsession)
and potentially [`LoginApprover`](#loginapprover) classes.

## Enums

### EAuthSessionSecurityHistory

```js
const {EAuthSessionSecurityHistory} = require('steam-session');
import {EAuthSessionSecurityHistory} from 'steam-session';
```

[View on GitHub](https://github.com/DoctorMcKay/node-steam-session/blob/master/src/enums-steam/EAuthSessionSecurityHistory.ts)

### EAuthSessionGuardType

```js
const {EAuthSessionGuardType} = require('steam-session');
import {EAuthSessionGuardType} from 'steam-session';
```

[View on GitHub](https://github.com/DoctorMcKay/node-steam-session/blob/master/src/enums-steam/EAuthSessionGuardType.ts)

Contains the possible auth session guards.

### EAuthTokenPlatformType

```js
const {EAuthTokenPlatformType} = require('steam-session');
import {EAuthTokenPlatformType} from 'steam-session';
```

[View on GitHub](https://github.com/DoctorMcKay/node-steam-session/blob/master/src/enums-steam/EAuthTokenPlatformType.ts)

Contains the different platform types that can be authenticated for. You should specify the correct platform type when
you instantiate a [`LoginSession`](#loginsession) object.

Audiences present in tokens issued for the different platform types:

- `SteamClient` - `['web', 'client']`
- `WebBrowser` - `['web']`
- `MobileApp` - `['web', 'mobile']`

### EResult

```js
const {EResult} = require('steam-session');
import {EResult} from 'steam-session';
```

[View on GitHub](https://github.com/DoctorMcKay/node-steam-session/blob/master/src/enums-steam/EResult.ts)

Contains possible result codes. This is a very large enum that used throughout Steam, so most values in this enum will
not be relevant when authenticating.

### ESessionPersistence

```js
const {ESessionPersistence} = require('steam-session');
import {ESessionPersistence} from 'steam-session';
```

[View on GitHub](https://github.com/DoctorMcKay/node-steam-session/blob/master/src/enums-steam/ESessionPersistence.ts)

Contains possible persistence levels for auth sessions.

## Custom Transports

It's possible to define a custom transport to be used when interacting with the Steam login server. The default transport
used to interact with the Steam login server is chosen depending on your provided [EAuthTokenPlatformType](#eauthtokenplatformtype).
For the `SteamClient` platform type, a `WebSocketCMTransport` will be used to communicate with a CM server using a WebSocket.
For other platform types, a `WebApiTransport` will be used to interact with the Steam login server using  api.steampowered.com.
**It is very likely that you won't need to mess with this.**

Everything in this category is TypeScript interfaces, so even if you're implementing a custom transport, you don't need
these unless you're using TypeScript.

```js
const {ITransport, ApiRequest, ApiResponse} = require('steam-session');
import {ITransport, ApiRequest, ApiResponse} from 'steam-session';
```

[View on GitHub](https://github.com/DoctorMcKay/node-steam-session/blob/master/src/transports/ITransport.ts)

# LoginSession

```js
const {LoginSession} = require('steam-session');
import {LoginSession} from 'steam-session';
```

The `LoginSession` class is the primary way to interact with steam-session.

## Properties

### steamID

**Read-only.** A [`SteamID`](https://www.npmjs.com/package/steamid) instance containing the SteamID for the
currently-authenticated account. Populated immediately after [`startWithCredentials`](#startwithcredentialsdetails)
resolves, or immediately after [`accessToken`](#accesstoken) or [`refreshToken`](#refreshtoken) are set (meaning that
this is always populated when [`authenticated`](#authenticated) fires).

### loginTimeout

A `number` specifying the time, in milliseconds, before a login attempt will [`timeout`](#timeout). The timer begins
after [`polling`](#polling) begins.

If you attempt to set this property after [`polling`](#polling) has already been emitted, an Error will be thrown since
setting this property after that point has no effect.

### accountName

**Read-only.** A `string` containing your account name. This is populated just before the [`authenticated`](#authenticated)
event is fired.

### accessToken

A `string` containing your access token. **As of 2023-09-12, Steam does not return an access token in response to
successful authentication, so this won't be set when the [`authenticated`](#authenticated) event is fired.** This will be set
after you call [`refreshAccessToken()`](#refreshaccesstoken) or [`renewRefreshToken()`](#renewrefreshtoken).
Also, since [`getWebCookies()`](#getwebcookies) calls `refreshAccessToken()` internally for EAuthTokenPlatformType
SteamClient or MobileApp, this will also be set after calling `getWebCookies()` for those platform types.

You can also assign an access token to this property if you already have one, although at present that wouldn't
do anything useful.

Setting this property will throw an Error if:

- You set it to a token that isn't well-formed, or
- You set it to a refresh token rather than an access token, or
- You have already called [`startWithCredentials`](#startwithcredentialsdetails) and you set it to a token that doesn't belong to the same account, or
- You have already set [`refreshToken`](#refreshtoken) and you set this to a token that doesn't belong to the same account as the refresh token

Access tokens can't be used for much. You can use them with a few undocumented WebAPIs like
[IFriendsListService/GetFriendsList](https://steamapi.xpaw.me/#IFriendsListService/GetFriendsList) by passing the access
token as an access_token query string parameter. For example:

    https://api.steampowered.com/IFriendsListService/GetFriendsList/v1/?access_token=eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0.eyJpc3MiOiJ...

As of time of writing (2023-04-24), it appears that you can also use access tokens with regular published API methods,
for example:

	https://api.steampowered.com/ISteamUserStats/GetNumberOfCurrentPlayers/v1/?appid=440&access_token=eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0.eyJpc3MiOiJ...

### refreshToken

A `string` containing your refresh token. This is populated just before the [`authenticated`](#authenticated) event is
fired. You can also assign a refresh token to this property if you already have one.

Setting this property will throw an Error if:

- You set it to a token that isn't well-formed, or
- You set it to an access token rather than a refresh token, or
- You have already called [`startWithCredentials`](#startwithcredentialsdetails) and you set it to a token that doesn't belong to the same account, or
- You have already set [`accessToken`](#accesstoken) and you set this to a token that doesn't belong to the same account as the access token

### steamGuardMachineToken

**Read-only.** A `string` containing your Steam Guard machine token. This is populated when you pass a `steamGuardMachineToken` to
[`startWithCredentials`](#startwithcredentialsdetails), or just before the [`steamGuardMachineToken`](#steamguardmachinetoken-1)
event is emitted.

## Methods

### Constructor(platformType[, options])
- `platformType` - A value from [`EAuthTokenPlatformType`](#eauthtokenplatformtype). You should set this to the
	appropriate platform type for your desired usage.
- `options` - An object with zero or more of these properties:
	- `userAgent` - Pass a user-agent string if you want to override the [default user-agent](https://github.com/DoctorMcKay/node-user-agents/blob/master/index.js).
        This is only effective when using EAuthTokenPlatformType.WebBrowser.
	- `transport` - An `ITransport` instance, if you need to specify a [custom transport](#custom-transports).
		If omitted, defaults to a `WebSocketCMTransport` instance for `SteamClient` platform types, and a 
		`WebApiTransport` instance for all other platform types. In all likelihood, you don't need to use this.
	- `localAddress` - A string containing the local IP address you want to use. For example, `11.22.33.44`
    - `httpProxy` - A string containing a URI for an HTTP proxy. For example, `http://user:pass@1.2.3.4:80`
    - `socksProxy` - A string containing a URI for a SOCKS proxy. For example, `socks5://user:pass@1.2.3.4:1080`
    - `agent` - An `https.Agent` instance to use for requests. If omitted, a new `https.Agent` will be created internally.
    - `machineId` - Only applicable when using EAuthTokenPlatformType.SteamClient. Pass a `Buffer` containing a valid
        Steam machine ID. Pass `true` to have steam-session internally generate a machine ID using the [same format that
        steam-user uses](https://github.com/DoctorMcKay/node-steam-user#machineidformat). Pass `false`, `null`, or omit
        this property to not send a machine ID (not sending a machine ID may cause problems in the future).

You can only use one of `localAddress`, `httpProxy`, `socksProxy` or `agent` at the same time. If you try to use more
than one of them, an Error will be thrown.

If you specify a custom transport, then you are responsible for handling proxy or agent usage in your transport.

Constructs a new `LoginSession` instance. Example usage:

```js
import {LoginSession, EAuthTokenPlatformType} from 'steam-session';

let session = new LoginSession(EAuthTokenPlatformType.WebBrowser);
```

### startWithCredentials(details)
- `details` - An object with these properties:
	- `accountName` - Your account's login name, as a string
    - `password` - Your account's password, as a string
    - `persistence` - Optional. A value from [ESessionPersistence](#esessionpersistence). Defaults to `Persistent`.
    - `steamGuardMachineToken` - Optional. If you have a valid Steam Guard machine token, supplying it here will allow
      you to bypass email code verification.
    - `steamGuardCode` - Optional. If you have a valid Steam Guard code (either email or TOTP), supplying it here will
      attempt to use it during login.

Starts a new login attempt using your account credentials. Returns a Promise.

If you're logging in with `EAuthTokenPlatformType.SteamClient`, you can supply a Buffer containing the SHA-1 hash of
your sentry file for `steamGuardMachineToken`. For example:

```js
import {createHash} from 'crypto';
import {readFileSync} from 'fs';
import {LoginSession, EAuthTokenPlatformType} from 'steam-session';

let hash = createHash('sha1');
hash.update(readFileSync('ssfn1234567890'));
let buffer = hash.digest(); // buffer contains a Buffer

let session = new LoginSession(EAuthTokenPlatformType.SteamClient);
session.startWithCredentials({
	accountName: 'johndoe',
	password: 'h3ll0wor1d',
	steamGuardMachineToken: buffer
});
```

If you supply a `steamGuardCode` here and you're using email-based Steam Guard, Steam will send you a new Steam Guard
email if you're using EAuthTokenPlatformType = SteamClient or MobileApp. You would ideally keep your LoginSession active
that generated your first email, and pass the code using [`submitSteamGuardCode`](#submitsteamguardcodeauthcode) instead
of creating a new LoginSession and supplying the code to `startWithCredentials`.

On failure, the Promise will be rejected with its message being equal to the string representation of an [EResult](#eresult)
value. There will also be an `eresult` property on the Error object equal to the numeric representation of the relevant
EResult value. For example:

```
Error: InvalidPassword
  eresult: 5
```

On success, the Promise will be resolved with an object containing these properties:

- `actionRequired` - A boolean indicating whether action is required from you to continue this login attempt.
  If false, you should expect for [`authenticated`](#authenticated) to be emitted shortly.
- `validActions` - If `actionRequired` is true, this is an array of objects indicating which actions you could take to
  continue this login attempt. Each object has these properties:
	- `type` - A value from [EAuthSessionGuardType](#eauthsessionguardtype)
    - `detail` - An optional string containing more details about this guard option. Right now, the only known use for
      this is that it contains your email address' domain for `EAuthSessionGuardType.EmailCode`.

Here's a list of which guard types might be present in this method's response, and how you should proceed:

- `EmailCode`: An email was sent to you containing a code (`detail` contains your email address' domain, e.g. `gmail.com`).
  You should get that code and either call [`submitSteamGuardCode`](#submitsteamguardcodeauthcode), or create a new
  `LoginSession` and supply that code to the `steamGuardCode` property when calling [`startWithCredentials`](#startwithcredentialsdetails).
- `DeviceCode`: You need to supply a TOTP code from your mobile authenticator (or by using [steam-totp](https://www.npmjs.com/package/steam-totp)).
  Get that code and either call [`submitSteamGuardCode`](#submitsteamguardcodeauthcode), or create a new `LoginSession`
  and supply that code to the `steamGuardCode` property when calling [`startWithCredentials`](#startwithcredentialsdetails).
- `DeviceConfirmation`: You need to approve the confirmation prompt in your Steam mobile app. If this guard type is
  present, [polling](#polling) will start and [`loginTimeout`](#logintimeout) will be in effect.
- `EmailConfirmation`: You need to approve the confirmation email sent to you. If this guard type is
  present, [polling](#polling) will start and [`loginTimeout`](#logintimeout) will be in effect.

Note that multiple guard types might be available; for example both `DeviceCode` and `DeviceConfirmation` can be
available at the same time.

When this method resolves, [`steamID`](#steamid) will be populated.

### startWithQR()

Starts a new QR login attempt. Returns a Promise.

On failure, the Promise will be rejected with its message being equal to the string representation of an [EResult](#eresult)
value. There will also be an `eresult` property on the Error object equal to the numeric representation of the relevant
EResult value. Realistically, failures should never happen unless Steam is having problems or you're having network issues.

On success, the Promise will be resolved with an object containing these properties:

- `actionRequired` - Always true.
- `validActions` - Same as `validActions` for [`startWithCredentials`](#startwithcredentialsdetails). `DeviceConfirmation`
  should always be present. `DeviceCode` has also been observed, even though at this point Steam doesn't even know what
  account you intend to log into.
- `qrChallengeUrl` - A string containing the URL that should be encoded into a QR code and then scanned with the Steam
  mobile app.

[`steamID`](#steamid) will not be populated when this method resolves, since at this point we don't know which account
we're going to log into. It will be populated after you successfully [authenticate](#authenticated).

Immediately after this resolves, LoginSession will start [polling](#polling) to determine when authentication has succeeded.

### submitSteamGuardCode(authCode)
- `authCode` - Your Steam Guard code, as a string

If a Steam Guard code is needed, you can supply it using this method. Returns a Promise.

On failure, the Promise will be rejected with its message being equal to the string representation of an [EResult](#eresult)
value. There will also be an `eresult` property on the Error object equal to the numeric representation of the relevant
EResult value. For example:

```
Error: TwoFactorCodeMismatch
  eresult: 88
```

Note that an incorrect email code will fail with EResult value InvalidLoginAuthCode (65), and an incorrect TOTP code
will fail with EResult value TwoFactorCodeMismatch (88).

On success, the Promise will be resolved with no value. In this case, you should expect for [`authenticated`](#authenticated)
to be emitted shortly.

### forcePoll()

Forces an immediate polling attempt. This will throw an `Error` if you call it before the [`polling`](#polling) event is
emitted, after [`authenticated`](#authenticated) is emitted, or after you call [`cancelLoginAttempt`](#cancelloginattempt).

### cancelLoginAttempt()

Cancels [polling](#polling) for an ongoing login attempt. Once canceled, you should no longer interact with this
`LoginSession` object, and you should create a new one if you want to start a new attempt.

### getWebCookies()

Once successfully [authenticated](#authenticated), you can call this method to get cookies for use on the Steam websites.
You can also manually set [`refreshToken`](#refreshtoken) and then call this method without going through another login
attempt if you already have a valid refresh token. Returns a Promise.

On failure, the Promise will be rejected. Depending on the nature of the failure, an EResult may or may not be available.

On success, the Promise will be resolved with an array of strings. Each string contains a cookie, e.g.
`'steamLoginSecure=blahblahblahblah'`.

Here's an example of how you can get new web cookies when you already have a valid refresh token:

```js
import {LoginSession, EAuthTokenPlatformType} from 'steam-session';

let session = new LoginSession(EAuthTokenPlatformType.WebBrowser);
session.refreshToken = 'eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0.eyJpc3MiOiJ...';
let cookies = await session.getWebCookies();
```

### refreshAccessToken()

As long as a [`refreshToken`](#refreshtoken) is set, you can call this method to obtain a new access token.
Returns a Promise.

On failure, the Promise will be rejected. An EResult will be available under the `eresult` property of the Error object.

On success, the Promise will be resolved with no value. You can then read the access token from the LoginSession's
accessToken property.

```js
import {LoginSession, EAuthTokenPlatformType} from 'steam-session';

let session = new LoginSession(EAuthTokenPlatformType.SteamClient);
session.refreshToken = 'eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0.eyJpc3MiOiJ...';
await session.refreshAccessToken();

console.log(`New access token: ${session.accessToken}`);
```

As of 2023-04-24, this method works for EAuthTokenPlatformType MobileApp and SteamClient, but using WebBrowser will fail
with response `AccessDenied`.

### renewRefreshToken()

Does the same thing as [`refreshAccessToken()`](#refreshaccesstoken), while also attempting to renew your refresh token.

Whether a new refresh token will actually be issued is at the discretion of the Steam backend. This method will
return true if a new refresh token was issued (which can be accessed using the [`refreshToken`](#refreshtoken) property), or
false if no new refresh token was issued. Regardless of the return value, the [`accessToken`](#accesstoken) property is
always updated with a fresh access token (unless there was an error).

**Important:** If a refresh token is successfully renewed (e.g. this method returns true), the old refresh token will
become invalid, even if it is not yet expired.

```js
import {LoginSession, EAuthTokenPlatformType} from 'steam-session';

let session = new LoginSession(EAuthTokenPlatformType.SteamClient);
session.refreshToken = 'eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0.eyJpc3MiOiJ...';
let renewed = await session.renewRefreshToken();

console.log(`New access token: ${session.accessToken}`);
if (renewed) {
	console.log(`New refresh token: ${session.refreshToken}`);
} else {
	console.log('No new refresh token was issued');
}
```

As of 2023-04-24, this method works for EAuthTokenPlatformType MobileApp and SteamClient, but using WebBrowser will fail
with response `AccessDenied`.

## Events

### polling

This event is emitted once we start polling Steam to periodically check if the login attempt has succeeded or not.
Polling starts when any of these conditions are met:

- A login session is successfully started with credentials and no guard is required (e.g. Steam Guard is disabled)*
- A login session is successfully started with credentials and you supplied a valid code to `steamGuardCode`*
- A login session is successfully started with credentials, you're using email Steam Guard, and you supplied a valid `steamGuardMachineToken`*
- A login session is successfully started with credentials, then you supplied a valid code to [`submitSteamGuardCode`](#submitsteamguardcodeauthcode)*
- A login session is successfully started, and `DeviceConfirmation` or `EmailConfirmation` are among the valid guards
	- This case covers [QR logins](#startwithqrdetails), since a QR login is a device confirmation under the hood

\* = in these cases, we expect to only have to poll once before login succeeds.

After this event is emitted, if your [`loginTimeout`](#logintimeout) elapses and the login attempt has not yet succeeded,
[`timeout`](#timeout) is emitted and the login attempt is abandoned. You would then need to start a new login attempt
using a fresh `LoginSession` object.

### timeout

This event is emitted when the time specified by [`loginTimeout`](#logintimeout) elapses after [polling](#polling) begins,
and the login attempt has not yet succeeded. When `timeout` is emitted, [`cancelLoginAttempt`](#cancelloginattempt) is
called internally.

### remoteInteraction

This event is emitted when Steam reports a "remote interaction" via [polling](#polling). This is observed to happen
when the approval prompt is viewed in the Steam mobile app for the `DeviceConfirmation` guard. For a [QR login](#startwithqrdetails),
this would be after you scan the code, but before you tap approve or deny.

### steamGuardMachineToken

This event is emitted when Steam sends us a new Steam Guard machine token. Machine tokens are only relevant when logging
into an account that has email-based Steam Guard enabled. Thus, this will only be emitted after successfully logging into
such an account.

At this time, this event is only emitted when logging in using EAuthTokenPlatformType = SteamClient. It's not presently
possible to get a machine token for the WebBrowser platform (and MobileApp platform doesn't support machine tokens at all).

When this event is emitted, the [`steamGuardMachineToken`](#steamguardmachinetoken) property contains your new machine
token.

### authenticated

This event is emitted when we successfully authenticate with Steam. At this point, [`accountName`](#accountname)
and [`refreshToken`](#refreshtoken) are populated. If the [EAuthTokenPlatformType](#eauthtokenplatformtype)
passed to the [constructor](#constructorplatformtype-transport) is appropriate, you can now safely call [`getWebCookies`](#getwebcookies).

### error

This event is emitted if we encounter an error while [polling](#polling). The first argument to the event handler is
an Error object. If this happens, the login attempt has failed and will need to be retried.

Node.js will crash if this event is emitted and not handled.

# LoginApprover

```js
const {LoginApprover} = require('steam-session');
import {LoginApprover} from 'steam-session';
```

This class can be used to approve a login attempt that was started with a QR code.
[See the approve-qr example.](https://github.com/DoctorMcKay/node-steam-session/blob/master/examples/approve-qr.ts)

## Properties

### steamID

**Read-only.** A [`SteamID`](https://www.npmjs.com/package/steamid) instance containing the SteamID for the
account to which the provided [`accessToken`](#accesstoken-1) belongs. Populated immediately after [`accessToken`](#accesstoken-1)
is set.

### accessToken

A `string` containing your access token. This is automatically set by the constructor, but you can also manually assign
it if you need to set a new access token.

An Error will be thrown when you set this property if you set it to a value that isn't a well-formed JWT, if you set it
to a refresh token rather than an access token, or if you set it to an access token that was not generated using
`EAuthTokenPlatformType.MobileApp`.

### sharedSecret

A `string` or `Buffer` containing your shared secret. This is automatically set by the constructor, but you can also
manually assign it if you need to set a new shared secret.

If this is a `string`, it must be either hex- or base64-encoded.

## Methods

### Constructor(accessToken, sharedSecret[, transport])
- `accessToken` - A `string` containing a valid access token for the account you want to approve logins for. This
  access token (**not refresh token**) must have been created using the `MobileApp` platform type.
- `sharedSecret` - A `string` or `Buffer` containing your account's TOTP shared secret. If this is a string, it must be
  hex- or base64-encoded.
- `options` - An object with zero or more of these properties:
	- `transport` - An `ITransport` instance, if you need to specify a [custom transport](#custom-transports).
	  If omitted, defaults to a `WebApiTransport` instance. In all likelihood, you don't need to use this.
    - `localAddress` - A string containing the local IP address you want to use. For example, `11.22.33.44`
	- `httpProxy` - A string containing a URI for an HTTP proxy. For example, `http://user:pass@1.2.3.4:80`
	- `socksProxy` A string containing a URI for a SOCKS proxy. For example, `socks5://user:pass@1.2.3.4:1080`
    - `agent` - An `https.Agent` instance to use for requests. If omitted, a new `https.Agent` will be created internally.

You can only use one of `localAddress`, `httpProxy`, `socksProxy` or `agent` at the same time. If you try to use more
than one of them, an Error will be thrown.

If you specify a custom transport, then you are responsible for handling proxy or agent usage in your transport.

Constructs a new `LoginApprover` instance. Example usage:

```js
import {LoginApprover} from 'steam-session';

let approver = new LoginApprover('eyAid...', 'oTVMfZJ9uHXo3m9MwTD9IOEWQaw=');
```

An Error will be thrown if your `accessToken` isn't a well-formed JWT, if it's a refresh token rather than an access
token, or if it's an access token that was not generated using `EAuthTokenPlatformType.MobileApp`.

### getAuthSessionInfo(qrChallengeUrl)
- `qrChallengeUrl` - A `string` containing the QR challenge URL from a [`startWithQR`](#startwithqrdetails) call

Returns a Promise which resolves to an object with these properties:

- `ip` - The origin IP address of the QR login attempt, as a string
- `location` - An object
	- `geoloc` - A string containing geo coordinates
    - `city` - String
    - `state` - String
- `platformType` - The [`EAuthTokenPlatformType`](#eauthtokenplatformtype) provided for the QR code
- `deviceFriendlyName` - The device name provided when the QR code was generated (likely a browser user-agent)
- `version` - A number containing the version from the QR code, probably not useful to you
- `loginHistory` - [`EAuthSessionSecurityHistory`](#eauthsessionsecurityhistory)
- `locationMismatch` - A boolean indicating whether the location you requested the auth session info from doesn't match
  the location where the QR code was generated
- `highUsageLogin` - A boolean indicating "whether this login has seen high usage recently"
- `requestedPersistence` - The [`ESessionPersistence`](#esessionpersistence) requested for this login

### approveAuthSession(details)
- `details` - An object with these properties:
	- `qrChallengeUrl` - A `string` containing the QR challenge URL from a [`startWithQR`](#startwithqrdetails) call
    - `approve` - `true` to approve the login or `false` to deny
    - `persistence` - An option value from [`ESessionPersistence`](#esessionpersistence)

Approves or denies an auth session from a QR URL. If you pass `true` for `approve`, then the next poll from the
`LoginSession` will return access tokens. If you pass `false`, then the `LoginSession` will emit an [`error`](#error)
event with [EResult](#eresult) `FileNotFound` (9).

Returns a Promise which resolves with no value. Once this Promise resolves, you could call [`forcePoll`](#forcepoll),
and the `LoginSession` should then immediately emit [`authenticated`](#authenticated).

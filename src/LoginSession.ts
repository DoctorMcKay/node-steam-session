import StdLib from '@doctormckay/stdlib';
import {HttpClient, HttpResponse} from '@doctormckay/stdlib/http';
import {randomBytes} from 'crypto';
import createDebug from 'debug';
import HTTPS from 'https';
import {SocksProxyAgent} from 'socks-proxy-agent';
import SteamID from 'steamid';
import {TypedEmitter} from 'tiny-typed-emitter';

import AuthenticationClient from './AuthenticationClient';
import {API_HEADERS, decodeJwt, eresultError, defaultUserAgent} from './helpers';

import WebApiTransport from './transports/WebApiTransport';
import WebSocketCMTransport from './transports/WebSocketCMTransport';

import {
	ConstructorOptions,
	StartLoginSessionWithCredentialsDetails,
	StartSessionResponse,
	StartSessionResponseValidAction
} from './interfaces-external';
import {
	StartAuthSessionResponse,
	StartAuthSessionWithCredentialsResponse,
	StartAuthSessionWithQrResponse
} from './interfaces-internal';

import EAuthSessionGuardType from './enums-steam/EAuthSessionGuardType';
import EAuthTokenPlatformType from './enums-steam/EAuthTokenPlatformType';
import EResult from './enums-steam/EResult';
import ESessionPersistence from './enums-steam/ESessionPersistence';

const debug = createDebug('steam-session:LoginSession');

import Timeout = NodeJS.Timeout;

/**
 * Unfortunately, IDE intellisense and the typedoc generator have two different means of defining events.
 * So, if an event is added, you need to add it both here and at the bottom of LoginSession as a static property.
 */
interface LoginSessionEvents {
	debug: (...any) => void,
	'debug-handler': (...any) => void,
	polling: () => void,
	authenticated: () => void,
	timeout: () => void,
	error: (Error) => void,
	remoteInteraction: () => void,
	steamGuardMachineToken: () => void
}

/**
 * Using CommonJS:
 * ```js
 * const {LoginSession} = require('steam-session');
 * ```
 *
 * Using ES6 modules:
 * ```js
 * import {LoginSession} from 'steam-session';
 * ```
 *
 * The {@link LoginSession} class is the primary way to interact with steam-session.
 *
 * @see Example: [login-with-password.ts](https://github.com/DoctorMcKay/node-steam-session/blob/master/examples/login-with-password.ts)
 * @see Example: [login-with-qr.ts](https://github.com/DoctorMcKay/node-steam-session/blob/master/examples/login-with-qr.ts)
 */
export default class LoginSession extends TypedEmitter<LoginSessionEvents> {
	private _loginTimeout: number;

	private _accountName?: string;
	private _accessToken?: string;
	private _refreshToken?: string;

	private _platformType: EAuthTokenPlatformType;
	private _webClient: HttpClient;
	private _handler: AuthenticationClient;

	private _steamGuardCode?: string;
	private _steamGuardMachineToken?: string;
	private _startSessionResponse?: StartAuthSessionResponse;
	private _hadRemoteInteraction?: boolean;

	private _pollingStartedTime?: number;
	private _pollTimer?: Timeout;
	private _pollingCanceled?: boolean;

	private _accessTokenSetAt?: Date;

	/**
	 * @param {EAuthTokenPlatformType} platformType - A value from {@link EAuthTokenPlatformType}.
	 * You should set this to the appropriate platform type for your desired usage.
	 * @param {ConstructorOptions} [options]
	 * @return
	 *
	 * Constructs a new `LoginSession` instance. Example usage:
	 *
	 * ```js
	 * import {LoginSession, EAuthTokenPlatformType} from 'steam-session';
	 *
	 * let session = new LoginSession(EAuthTokenPlatformType.WebBrowser);
	 * ```
	 */
	constructor(platformType: EAuthTokenPlatformType, options?: ConstructorOptions) {
		super();

		options = options || {};

		let mutuallyExclusiveOptions = ['localAddress', 'httpProxy', 'socksProxy', 'agent'];
		if (Object.keys(options).filter(k => mutuallyExclusiveOptions.includes(k)).length > 1) {
			throw new Error('Cannot specify more than one of localAddress, httpProxy, socksProxy, or agent at the same time');
		}

		let agent:HTTPS.Agent = options.agent || new HTTPS.Agent({keepAlive: true});

		if (options.httpProxy) {
			agent = StdLib.HTTP.getProxyAgent(true, options.httpProxy) as HTTPS.Agent;
		} else if (options.socksProxy) {
			agent = new SocksProxyAgent(options.socksProxy);
		}

		this._webClient = new HttpClient({
			httpsAgent: agent,
			localAddress: options.localAddress
		});

		this._platformType = platformType;

		let transport = options.transport;
		if (!transport) {
			switch (platformType) {
				case EAuthTokenPlatformType.SteamClient:
					transport = new WebSocketCMTransport(this._webClient, agent, options.localAddress);
					break;

				default:
					transport = new WebApiTransport(this._webClient);
			}
		}

		this._handler = new AuthenticationClient({
			platformType: this._platformType,
			transport,
			webClient: this._webClient,
			webUserAgent: options.userAgent || defaultUserAgent(),
			machineId: options.machineId
		});
		this._handler.on('debug', (...args) => this.emit('debug-handler', ...args));
		this.on('debug', debug);

		this.loginTimeout = 30000;
	}

	/**
	 * A `number` specifying the time, in milliseconds, before a login attempt will {@link timeout}. The timer begins
	 * after {@link polling} begins.
	 *
	 * If you attempt to set this property after {@link polling} has already been emitted, an Error will be thrown since
	 * setting this property after that point has no effect.
	 */
	get loginTimeout(): number {
		return this._loginTimeout;
	}

	set loginTimeout(value: number) {
		if (this._pollingStartedTime) {
			throw new Error('Setting loginTimeout after polling has already started is ineffective');
		}

		this._loginTimeout = value;
	}

	/**
	 * **Read-only.** A [`SteamID`](https://www.npmjs.com/package/steamid) instance containing the SteamID for the
	 * currently-authenticated account. Populated immediately after {@link startWithCredentials}
	 * resolves, or immediately after {@link accessToken} or {@link refreshToken} are set (meaning that
	 * this is always populated when {@link authenticated} fires).
	 */
	get steamID(): SteamID {
		// There's a few places we could get a steamid from
		if (this._startSessionResponse && (this._startSessionResponse as StartAuthSessionWithCredentialsResponse).steamId) {
			return new SteamID((this._startSessionResponse as StartAuthSessionWithCredentialsResponse).steamId);
		} else if (this.accessToken || this.refreshToken) {
			let token = this.accessToken || this.refreshToken;
			let decodedToken = decodeJwt(token);
			return new SteamID(decodedToken.sub);
		} else {
			return null;
		}
	}

	/**
	 * **Read-only.** A `string` containing your account name. This is populated just before the {@link authenticated}
	 * event is fired.
	 */
	get accountName(): string { return this._accountName; }

	/**
	 * A `string` containing your access token. As of 2023-09-12, Steam does not return an access token in response to
	 * successful authentication, so this won't be set when the {@link authenticated} event is fired. This will be set
	 * after you call {@link refreshAccessToken} or {@link renewRefreshToken}. Also, since {@link getWebCookies} calls
	 * {@link refreshAccessToken} internally for {@link EAuthTokenPlatformType.SteamClient | EAuthTokenPlatformType.SteamClient}
	 * or {@link EAuthTokenPlatformType.MobileApp | MobileApp}, this will also be set after calling {@link getWebCookies}
	 * for those platform types.
	 *
	 * You can also assign an access token to this property if you already have one, although at present that wouldn't
	 * do anything useful.
	 *
	 * Setting this property will throw an Error if:
	 *
	 * - You set it to a token that isn't well-formed, or
	 * - You set it to a refresh token rather than an access token, or
	 * - You have already called {@link startWithCredentials} and you set it to a token that doesn't belong to the same account, or
	 * - You have already set {@link refreshToken} and you set this to a token that doesn't belong to the same account as the refresh token
	 *
	 * Access tokens can't be used for much. You can use them with a few undocumented WebAPIs like
	 * [IFriendsListService/GetFriendsList](https://steamapi.xpaw.me/#IFriendsListService/GetFriendsList) by passing the access
	 * token as an access_token query string parameter. For example:
	 *
	 *     https://api.steampowered.com/IFriendsListService/GetFriendsList/v1/?access_token=eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0.eyJpc3MiOiJ...
	 *
	 * As of time of writing (2023-04-24), it appears that you can also use access tokens with regular published API methods,
	 * for example:
	 *
	 *     https://api.steampowered.com/ISteamUserStats/GetNumberOfCurrentPlayers/v1/?appid=440&access_token=eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0.eyJpc3MiOiJ...
	 *
	 * node-steamcommunity also has a method you can use to provide it with an access token:
	 * [`setMobileAppAccessToken`](https://github.com/DoctorMcKay/node-steamcommunity/wiki/SteamCommunity#setmobileappaccesstokenaccesstoken)
	 */
	get accessToken(): string { return this._accessToken; }
	set accessToken(token: string) {
		if (!token) {
			this._accessToken = token;
			return;
		}

		let decoded = decodeJwt(token);

		try { new SteamID(decoded.sub); } catch {
			throw new Error('Not a valid Steam token');
		}

		let aud = decoded.aud || [];
		if (aud.includes('derive')) {
			throw new Error('The provided token is a refresh token, not an access token');
		}

		if (
			this._startSessionResponse
			&& (this._startSessionResponse as StartAuthSessionWithCredentialsResponse).steamId
			&& decoded.sub != (this._startSessionResponse as StartAuthSessionWithCredentialsResponse).steamId
		) {
			throw new Error('Token is for a different account. To work with a different account, create a new LoginSession.');
		}

		if (this._refreshToken) {
			let decodedRefreshToken = decodeJwt(this._refreshToken);
			if (decodedRefreshToken.sub != decoded.sub) {
				throw new Error('This access token belongs to a different account from the set refresh token.');
			}
		}

		// Everything checks out
		this._accessToken = token;
		this._accessTokenSetAt = new Date();
	}

	/**
	 * A `string` containing your refresh token. This is populated just before the {@link authenticated} event is fired.
	 * You can also assign a refresh token to this property if you already have one.
	 *
	 * Setting this property will throw an Error if:
	 *
	 * - You set it to a token that isn't well-formed, or
	 * - You set it to an access token rather than a refresh token, or
	 * - You have already called {@link startWithCredentials} and you set it to a token that doesn't belong to the same account, or
	 * - You have already set {@link accessToken} and you set this to a token that doesn't belong to the same account as the access token
	 */
	get refreshToken(): string { return this._refreshToken; }
	set refreshToken(token: string) {
		if (!token) {
			this._refreshToken = token;
			return;
		}

		let decoded = decodeJwt(token);

		try { new SteamID(decoded.sub); } catch {
			throw new Error('Not a valid Steam token');
		}

		let aud = decoded.aud || [];
		if (!aud.includes('derive')) {
			throw new Error('The provided token is an access token, not a refresh token');
		}

		let requiredAudience = 'unknown';
		switch (this._platformType) {
			case EAuthTokenPlatformType.SteamClient:
				requiredAudience = 'client';
				break;

			case EAuthTokenPlatformType.MobileApp:
				requiredAudience = 'mobile';
				break;

			case EAuthTokenPlatformType.WebBrowser:
				requiredAudience = 'web';
				break;
		}

		if (!aud.includes(requiredAudience)) {
			throw new Error(`Token platform type is different from the platform type of this LoginSession instance (required audience "${requiredAudience}" but got "${aud.join(',')}"`);
		}

		if (
			this._startSessionResponse
			&& (this._startSessionResponse as StartAuthSessionWithCredentialsResponse).steamId
			&& decoded.sub != (this._startSessionResponse as StartAuthSessionWithCredentialsResponse).steamId
		) {
			throw new Error('Token is for a different account. To work with a different account, create a new LoginSession.');
		}

		if (this._accessToken) {
			let decodedAccessToken = decodeJwt(this._accessToken);
			if (decodedAccessToken.sub != decoded.sub) {
				throw new Error('This refresh token belongs to a different account from the set access token.');
			}
		}

		// Everything checks out
		this._refreshToken = token;
	}

	/**
	 * **Read-only.** A `string` containing your Steam Guard machine token. This is populated when you pass a `steamGuardMachineToken` to
	 * {@link startWithCredentials}, or just before the {@link steamGuardMachineToken} event is emitted.
	 */
	get steamGuardMachineToken(): string { return this._steamGuardMachineToken; }

	private get _defaultWebsiteId() {
		switch (this._platformType) {
			case EAuthTokenPlatformType.SteamClient:
				return 'Client';

			case EAuthTokenPlatformType.WebBrowser:
				return 'Community';

			case EAuthTokenPlatformType.MobileApp:
				return 'Mobile';

			default:
				return 'Community';
		}
	}

	private _verifyStarted(mustHaveSteamId = false) {
		if (!this._startSessionResponse) {
			throw new Error('Login session has not been started yet');
		}

		if (this._pollingCanceled) {
			throw new Error('Login attempt has been canceled');
		}

		if (mustHaveSteamId && !this.steamID) {
			throw new Error('Cannot use this method with this login scheme');
		}
	}

	/**
	 * @param details
	 * @return
	 *
	 * Starts a new login attempt using your account credentials. Returns a Promise.
	 *
	 * If you're logging in with {@link EAuthTokenPlatformType.SteamClient | EAuthTokenPlatformType.SteamClient}, you
	 * can supply a Buffer containing the SHA-1 hash of your sentry file for
	 * {@link StartLoginSessionWithCredentialsDetails.steamGuardMachineToken}.
	 *
	 * For example:
	 *
	 *
	 * ```js
	 * import {createHash} from 'crypto';
	 * import {readFileSync} from 'fs';
	 * import {LoginSession, EAuthTokenPlatformType} from 'steam-session';
	 *
	 * let hash = createHash('sha1');
	 * hash.update(readFileSync('ssfn1234567890'));
	 * let buffer = hash.digest(); // buffer contains a Buffer
	 *
	 * let session = new LoginSession(EAuthTokenPlatformType.SteamClient);
	 * session.startWithCredentials({
	 *     accountName: 'johndoe',
	 *     password: 'h3ll0wor1d',
	 *     steamGuardMachineToken: buffer
	 * });
	 * ```
	 *
	 * If you supply a {@link StartLoginSessionWithCredentialsDetails.steamGuardCode} here and you're using email-based
	 * Steam Guard, Steam will send you a new Steam Guard email if you're using {@link EAuthTokenPlatformType.SteamClient | EAuthTokenPlatformType.SteamClient}
	 * or {@link EAuthTokenPlatformType.MobileApp}. You would ideally keep your LoginSession active that generated your
	 * first email, and pass the code using {@link submitSteamGuardCode} instead of creating a new LoginSession and
	 * supplying the code to {@link startWithCredentials}.
	 *
	 * On failure, the Promise will be rejected with its message being equal to the string representation of an {@link EResult}
	 * value. There will also be an `eresult` property on the Error object equal to the numeric representation of the relevant
	 * EResult value. For example:
	 *
	 * ```
	 * Error: InvalidPassword
	 *   eresult: 5
	 * ```
	 *
	 * On success, the Promise will be resolved with a {@link StartSessionResponse} object.
	 *
	 * Here's a list of which guard types might be present in this method's response, and how you should proceed:
	 *
	 * - {@link EAuthSessionGuardType.EmailCode}: An email was sent to you containing a code
	 *   (`detail` contains your email address' domain, e.g. `gmail.com`).
	 *   You should get that code and either call {@link submitSteamGuardCode}, or create a new {@link LoginSession}
	 *   and supply that code to the {@link StartLoginSessionWithCredentialsDetails.steamGuardCode} property when calling
	 *   {@link startWithCredentials}.
	 * - {@link EAuthSessionGuardType.DeviceCode}: You need to supply a TOTP code from your mobile authenticator
	 *   (or by using [steam-totp](https://www.npmjs.com/package/steam-totp)).
	 *   Get that code and either call {@link submitSteamGuardCode}, or create a new {@link LoginSession} and supply that
	 *   code to the {@link StartLoginSessionWithCredentialsDetails.steamGuardCode} property when calling {@link startWithCredentials}.
	 * - {@link EAuthSessionGuardType.DeviceConfirmation}: You need to approve the confirmation prompt in your Steam
	 *   mobile app. If this guard type is present, {@link polling} will start and {@link loginTimeout} will be in effect.
	 * - {@link EAuthSessionGuardType.EmailConfirmation}: You need to approve the confirmation email sent to you. If this
	 *   guard type is present, {@link polling} will start and {@link loginTimeout} will be in effect.
	 *
	 * Note that multiple guard types might be available; for example both {@link EAuthSessionGuardType.DeviceCode} and
	 * {@link EAuthSessionGuardType.DeviceConfirmation} can be available at the same time.
	 *
	 * When this method resolves, {@link steamID} will be populated.
	 */
	async startWithCredentials(details: StartLoginSessionWithCredentialsDetails): Promise<StartSessionResponse> {
		if (this._startSessionResponse) {
			throw new Error('A session has already been started on this LoginSession object. Create a new LoginSession to start a new session.');
		}

		this._hadRemoteInteraction = false;
		this._steamGuardCode = details.steamGuardCode;

		if (typeof details.steamGuardMachineToken == 'string') {
			this._steamGuardMachineToken = details.steamGuardMachineToken;
		}

		let encryptionResult = await this._handler.encryptPassword(details.accountName, details.password);

		this._startSessionResponse = await this._handler.startSessionWithCredentials({
			accountName: details.accountName,
			...encryptionResult,
			persistence: details.persistence || ESessionPersistence.Persistent,
			platformType: this._platformType,
			// use a manually-specified token with priority over a token saved on this object
			steamGuardMachineToken: details.steamGuardMachineToken || this.steamGuardMachineToken
		});

		this.emit('debug', 'start session response', this._startSessionResponse);

		return await this._processStartSessionResponse();
	}

	/**
	 * @return
	 *
	 * Starts a new QR login attempt. Returns a Promise.
	 *
	 * On failure, the Promise will be rejected with its message being equal to the string representation of an {@link EResult}
	 * value. There will also be an `eresult` property on the Error object equal to the numeric representation of the relevant
	 * EResult value. Realistically, failures should never happen unless Steam is having problems or you're having network issues.
	 *
	 * On success, the Promise will be resolved with a {@link StartSessionResponse} object.
	 *
	 * {@link steamID} will not be populated when this method resolves, since at this point we don't know which account
	 * we're going to log into. It will be populated after you successfully {@link authenticated | authenticate}.
	 *
	 * Immediately after this resolves, {@link LoginSession} will start {@link polling} to determine when authentication
	 * has succeeded.
	 */
	async startWithQR(): Promise<StartSessionResponse> {
		if (this._startSessionResponse) {
			throw new Error('A session has already been started on this LoginSession object. Create a new LoginSession to start a new session.');
		}

		this._hadRemoteInteraction = false;

		this._startSessionResponse = await this._handler.startSessionWithQR();

		this.emit('debug', 'start qr session response', this._startSessionResponse);

		return await this._processStartSessionResponse();
	}

	private async _processStartSessionResponse(): Promise<StartSessionResponse> {
		this._pollingCanceled = false;

		let validActions:StartSessionResponseValidAction[] = [];

		for (let i of this._startSessionResponse.allowedConfirmations) {
			switch (i.type) {
				case EAuthSessionGuardType.None:
					this.emit('debug', 'no guard required');
					// Use setImmediate here so that the promise is resolved before we potentially emit a session
					setImmediate(() => this._doPoll());
					return {actionRequired: false};

				case EAuthSessionGuardType.EmailCode:
				case EAuthSessionGuardType.DeviceCode:
					let codeType = i.type == EAuthSessionGuardType.EmailCode ? 'email' : 'device';
					this.emit('debug', `${codeType} code required`);

					let authResult = await (codeType == 'email' ? this._attemptEmailCodeAuth() : this._attemptTotpCodeAuth());
					if (authResult) {
						// We successfully authed already, no action needed
						return {actionRequired: false};
					} else {
						// We need a code from the user
						let action:StartSessionResponseValidAction = {type: i.type};
						if (i.message) {
							action.detail = i.message;
						}
						validActions.push(action);
						break;
					}

				case EAuthSessionGuardType.DeviceConfirmation:
				case EAuthSessionGuardType.EmailConfirmation:
					this.emit('debug', 'device or email confirmation guard required');
					validActions.push({type: i.type});
					setImmediate(() => this._doPoll());
					break;

				case EAuthSessionGuardType.MachineToken:
					// Do nothing here since this is handled by _attemptEmailCodeAuth
					break;

				default:
					let guardTypeString:string = i.type.toString();
					for (let j in EAuthSessionGuardType) {
						if (EAuthSessionGuardType[j] == guardTypeString) {
							guardTypeString = j;
							break;
						}
					}

					throw new Error(`Unknown auth session guard type ${guardTypeString}`);
			}
		}

		// If we got here but we have no valid actions, something went wrong
		if (validActions.length == 0) {
			throw new Error('Login requires action, but we can\'t tell what kind of action is required');
		}

		let response:StartSessionResponse = {
			actionRequired: true,
			validActions
		};

		if ((this._startSessionResponse as StartAuthSessionWithQrResponse).challengeUrl) {
			let startSessionResponse:StartAuthSessionWithQrResponse = this._startSessionResponse as StartAuthSessionWithQrResponse;
			response.qrChallengeUrl = startSessionResponse.challengeUrl;
		}

		return response;
	}

	/**
	 * @return
	 *
	 * Forces an immediate polling attempt. This will throw an `Error` if you call it before the {@link polling} event is
	 * emitted, after {@link authenticated} is emitted, or after you call {@link cancelLoginAttempt}.
	 */
	forcePoll() {
		this._verifyStarted();

		if (!this._pollingStartedTime) {
			throw new Error('Polling has not yet started');
		}

		this._doPoll();
	}

	private async _doPoll() {
		if (this._pollingCanceled) {
			return;
		}

		// If we called _doPoll outside of an existing timer, cancel the timer
		clearTimeout(this._pollTimer);

		if (!this._pollingStartedTime) {
			this._pollingStartedTime = Date.now();
			this.emit('polling');
		}

		let totalPollingTime = Date.now() - this._pollingStartedTime;
		if (totalPollingTime >= this.loginTimeout) {
			this.emit('timeout');
			this.cancelLoginAttempt();
			return;
		}

		let pollResponse;
		try {
			pollResponse = await this._handler.pollLoginStatus(this._startSessionResponse);
			this.emit('debug', 'poll response', pollResponse);
		} catch (ex) {
			// If we got an error, but we've already canceled polling, just do nothing.
			if (!this._pollingCanceled) {
				this.emit('error', ex);
				this.cancelLoginAttempt();
			}
			return;
		}

		this._startSessionResponse.clientId = pollResponse.newClientId || this._startSessionResponse.clientId;

		if (pollResponse.hadRemoteInteraction && !this._hadRemoteInteraction) {
			this._hadRemoteInteraction = true;
			this.emit('remoteInteraction');
		}

		if (pollResponse.newSteamGuardMachineAuth) {
			this._steamGuardMachineToken = pollResponse.newSteamGuardMachineAuth;
			this.emit('steamGuardMachineToken');
		}

		if (pollResponse.refreshToken) {
			this._accountName = pollResponse.accountName;
			this.refreshToken = pollResponse.refreshToken;
			this.accessToken = pollResponse.accessToken || null;

			// On 2023-09-12, Steam stopped issuing access tokens alongside refresh tokens for newly authenticated sessions.
			// This won't affect any consumer apps that use `getWebCookies()`, since that will acquire an access token if
			// needed.
			// On 2023-09-22, I noticed that Steam started issuing access tokens again. ¯\_(ツ)_/¯

			// Consumers using SteamClient or WebBrowser never had a reason to consume the accessToken property directly,
			// since that was only useful as a cookie and `getWebCookies()` should be used instead. However, the access
			// token is also used as a WebAPI key for MobileApp, so we should probably ensure that we have one for that
			// platform.
			if (!this.accessToken && this._platformType == EAuthTokenPlatformType.MobileApp) {
				await this.refreshAccessToken();
			}

			this.emit('authenticated');
			this.cancelLoginAttempt();
		} else if (!this._pollingCanceled) {
			this._pollTimer = setTimeout(() => this._doPoll(), this._startSessionResponse.pollInterval * 1000);
		}
	}

	/**
	 * @returns {boolean} - true if code submitted successfully, false if code wasn't valid or no code available
	 */
	private async _attemptEmailCodeAuth(): Promise<boolean> {
		if (this._steamGuardCode) {
			try {
				await this.submitSteamGuardCode(this._steamGuardCode);
				return true;
			} catch (ex) {
				if (ex.eresult != EResult.InvalidLoginAuthCode) {
					// this is some kind of important error
					throw ex;
				}
			}
		}

		// Can we use a machine auth token?
		if (
			this._platformType == EAuthTokenPlatformType.WebBrowser
			&& this._startSessionResponse.allowedConfirmations.some(c => c.type == EAuthSessionGuardType.MachineToken)
		) {
			let result = await this._handler.checkMachineAuthOrSendCodeEmail({
				machineAuthToken: this.steamGuardMachineToken,
				...(this._startSessionResponse as StartAuthSessionWithCredentialsResponse)
			});

			this.emit('debug', `machine auth check response: ${EResult[result.result]}`);

			if (result.result == EResult.OK) {
				// Machine auth succeeded
				setImmediate(() => this._doPoll());
				return true;
			}
		}

		// An email was sent
		return false;
	}

	private async _attemptTotpCodeAuth(): Promise<boolean> {
		if (this._steamGuardCode) {
			try {
				await this.submitSteamGuardCode(this._steamGuardCode);
				return true; // submitting code succeeded
			} catch (ex) {
				if (ex.eresult != EResult.TwoFactorCodeMismatch) {
					// this is some kind of important error
					throw ex;
				}
			}
		}

		// If we got here, then we need the user to supply a code
		return false;
	}

	/**
	 * @param authCode - Your Steam Guard code
	 * @return
	 *
	 * If a Steam Guard code is needed, you can supply it using this method. Returns a Promise.
	 *
	 * On failure, the Promise will be rejected with its message being equal to the string representation of an {@link EResult}
	 * value. There will also be an `eresult` property on the Error object equal to the numeric representation of the relevant
	 * EResult value. For example:
	 *
	 * ```
	 * Error: TwoFactorCodeMismatch
	 *   eresult: 88
	 * ```
	 *
	 * Note that an incorrect email code will fail with EResult value {@link EResult.InvalidLoginAuthCode} (65), and an
	 * incorrect TOTP code will fail with EResult value {@link EResult.TwoFactorCodeMismatch} (88).
	 *
	 * On success, the Promise will be resolved with no value. In this case, you should expect for {@link authenticated}
	 * to be emitted shortly.
	 */
	async submitSteamGuardCode(authCode: string): Promise<void> {
		this._verifyStarted(true);

		this.emit('debug', 'submitting steam guard code', authCode);

		let needsEmailCode = this._startSessionResponse.allowedConfirmations.some(c => c.type == EAuthSessionGuardType.EmailCode);
		let needsTotpCode = this._startSessionResponse.allowedConfirmations.some(c => c.type == EAuthSessionGuardType.DeviceCode);
		if (!needsEmailCode && !needsTotpCode) {
			throw new Error('No Steam Guard code is needed for this login attempt');
		}

		await this._handler.submitSteamGuardCode({
			...(this._startSessionResponse as StartAuthSessionWithCredentialsResponse),
			authCode,
			authCodeType: needsEmailCode ? EAuthSessionGuardType.EmailCode : EAuthSessionGuardType.DeviceCode
		});

		setImmediate(() => this._doPoll());
	}

	/**
	 * @return - True if we were actively polling and it has now been canceled. False if we were not polling.
	 *
	 * Cancels {@link polling} for an ongoing login attempt. Once canceled, you should no longer interact with this
	 * {@link LoginSession} object, and you should create a new one if you want to start a new attempt.
	 */
	cancelLoginAttempt(): boolean {
		this._pollingCanceled = true;
		this._handler.close();

		if (this._pollTimer) {
			clearTimeout(this._pollTimer);
			return true;
		}

		return false;
	}

	/**
	 * @return
	 *
	 * Once successfully {@link authenticated}, you can call this method to get cookies for use on the Steam websites.
	 * You can also manually set {@link refreshToken} and then call this method without going through another login
	 * attempt if you already have a valid refresh token. Returns a Promise.
	 *
	 * On failure, the Promise will be rejected. Depending on the nature of the failure, an {@link EResult} may or may
	 * not be available.
	 *
	 * On success, the Promise will be resolved with an array of strings. Each string contains a cookie, e.g.
	 * `'steamLoginSecure=blahblahblahblah'`.
	 *
	 * Here's an example of how you can get new web cookies when you already have a valid refresh token:
	 *
	 * ```js
	 * import {LoginSession, EAuthTokenPlatformType} from 'steam-session';
	 *
	 * let session = new LoginSession(EAuthTokenPlatformType.WebBrowser);
	 * session.refreshToken = 'eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0.eyJpc3MiOiJ...';
	 * let cookies = await session.getWebCookies();
	 * ```
	 */
	async getWebCookies(): Promise<string[]> {
		if (!this.refreshToken) {
			throw new Error('A refresh token is required to get web cookies');
		}

		let sessionId = randomBytes(12).toString('hex');

		// If our platform type is MobileApp or SteamClient, then our access token *is* our session cookie.
		// The same is likely true for WebBrowser, but we want to mimic official behavior as closely as possible to avoid
		// any potential future breakage.
		if ([EAuthTokenPlatformType.SteamClient, EAuthTokenPlatformType.MobileApp].includes(this._platformType)) {
			if (!this.accessToken || Date.now() - this._accessTokenSetAt.getTime() > (1000 * 60 * 10)) {
				// Refresh our access token if we either don't have one, or the token we have is greater than 10 minutes old
				await this.refreshAccessToken();
			}

			let cookieValue = encodeURIComponent([this.steamID.getSteamID64(), this.accessToken].join('||'));
			return [`steamLoginSecure=${cookieValue}`, `sessionid=${sessionId}`];
		}

		let body = {
			nonce: this.refreshToken,
			sessionid: sessionId,
			redir: 'https://steamcommunity.com/login/home/?goto='
		};

		debug('POST https://login.steampowered.com/jwt/finalizelogin %o', body);
		let finalizeResponse = await this._webClient.request({
			method: 'POST',
			url: 'https://login.steampowered.com/jwt/finalizelogin',
			headers: API_HEADERS,
			multipartForm: HttpClient.simpleObjectToMultipartForm(body)
		});

		if (finalizeResponse.jsonBody && finalizeResponse.jsonBody.error) {
			throw eresultError(finalizeResponse.jsonBody.error);
		}

		if (!finalizeResponse.jsonBody || !finalizeResponse.jsonBody.transfer_info) {
			let err:any = new Error('Malformed login response');
			err.responseBody = finalizeResponse.jsonBody;
			throw err;
		}

		// Now we want to execute all transfers specified in the finalizelogin response. Technically we only need one
		// successful transfer (hence the usage of promsieAny), but we execute them all for robustness in case one fails.
		// As long as one succeeds, we're good.
		let transfers = finalizeResponse.jsonBody.transfer_info.map(({url, params}) => new Promise(async (resolve, reject) => {
			let body = {steamID: this.steamID.getSteamID64(), ...params};
			debug('POST %s %o', url, body);

			let result: HttpResponse;
			try {
				result = await this._webClient.request({
					method: 'POST',
					url,
					multipartForm: HttpClient.simpleObjectToMultipartForm(body)
				});
			} catch (error) {
				return reject(error);
			}

			if (!result.headers || !result.headers['set-cookie'] || result.headers['set-cookie'].length == 0) {
				return reject(new Error('No Set-Cookie header in result'));
			}

			if (!result.headers['set-cookie'].some(c => c.startsWith('steamLoginSecure='))) {
				return reject(new Error('No steamLoginSecure cookie in result'));
			}

			resolve(result.headers['set-cookie'].map(c => c.split(';')[0].trim()));
		}));

		let cookies = await promiseAny(transfers) as string[];
		if (!cookies.some((c) => c.includes('sessionid'))) {
			cookies.push(`sessionid=${sessionId}`);
		}

		return cookies;
	}

	/**
	 * @return
	 *
	 * As long as a {@link refreshToken} is set, you can call this method to obtain a new access token.
	 * Returns a Promise.
	 *
	 * On failure, the Promise will be rejected. An {@link EResult} will be available under the `eresult` property of
	 * the Error object.
	 *
	 * On success, the Promise will be resolved with no value. You can then read the access token from the LoginSession's
	 * {@link accessToken} property.
	 *
	 * ```js
	 * import {LoginSession, EAuthTokenPlatformType} from 'steam-session';
	 *
	 * let session = new LoginSession(EAuthTokenPlatformType.WebBrowser);
	 * session.refreshToken = 'eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0.eyJpc3MiOiJ...';
	 * await session.refreshAccessToken();
	 *
	 * console.log(`New access token: ${session.accessToken}`);
	 * ```
	 *
	 * As of 2023-04-24, this method works for {@link EAuthTokenPlatformType.MobileApp | EAuthTokenPlatformType.MobileApp}
	 * and {@link EAuthTokenPlatformType.SteamClient}, but using {@link EAuthTokenPlatformType.WebBrowser} will fail
	 * with response {@link EResult.AccessDenied}.
	 */
	async refreshAccessToken(): Promise<void> {
		if (!this.refreshToken) {
			throw new Error('A refresh token is required to get a new access token');
		}

		this.accessToken = (await this._handler.generateAccessTokenForApp(this.refreshToken)).accessToken;
	}

	/**
	 * @return boolean
	 *
	 * Does the same thing as {@link refreshAccessToken}, while also attempting to renew your refresh token.
	 *
	 * Whether a new refresh token will actually be issued is at the discretion of the Steam backend. This method will
	 * return true if a new refresh token was issued (which can be accessed using the {@link refreshToken} property), or
	 * false if no new refresh token was issued. Regardless of the return value, the {@link accessToken} property is
	 * always updated with a fresh access token (unless there was an error).
	 *
	 * **Important:** If a refresh token is successfully renewed (e.g. this method returns true), the old refresh token
	 * will become invalid, even if it is not yet expired.
	 */
	async renewRefreshToken(): Promise<boolean> {
		if (!this.refreshToken) {
			throw new Error('A refresh token is required to get a new access token');
		}

		let {accessToken, refreshToken} = await this._handler.generateAccessTokenForApp(this.refreshToken, true);
		this.accessToken = accessToken;
		this.refreshToken = refreshToken || this.refreshToken;

		return !!refreshToken;
	}

	////////////////////////////
	// DOCS FOR EVENTS FOLLOW //
	////////////////////////////

	/**
	 * This event is emitted once we start polling Steam to periodically check if the login attempt has succeeded or not.
	 * Polling starts when any of these conditions are met:
	 *
	 * - A login session is successfully started with credentials and no guard is required (e.g. Steam Guard is disabled)*
	 * - A login session is successfully started with credentials and you supplied a valid code to {@link StartLoginSessionWithCredentialsDetails.steamGuardCode}*
	 * - A login session is successfully started with credentials, you're using email Steam Guard, and you supplied a valid {@link StartLoginSessionWithCredentialsDetails.steamGuardMachineToken}*
	 * - A login session is successfully started with credentials, then you supplied a valid code to {@link submitSteamGuardCode}*
	 * - A login session is successfully started, and {@link EAuthSessionGuardType.DeviceConfirmation} or {@link EAuthSessionGuardType.EmailConfirmation} are among the valid guards
	 * 	 - This case covers {@link startWithQR | QR logins}, since a QR login is a device confirmation under the hood
	 *
	 * \* = in these cases, we expect to only have to poll once before login succeeds.
	 *
	 * After this event is emitted, if your {@link loginTimeout} elapses and the login attempt has not yet succeeded,
	 * {@link timeout} is emitted and the login attempt is abandoned. You would then need to start a new login attempt
	 * using a fresh {@link LoginSession} object.
	 *
	 * @event
	 */
	static polling = 'polling';

	/**
	 * This event is emitted when the time specified by {@link loginTimeout} elapses after {@link polling} begins, and
	 * the login attempt has not yet succeeded. When `timeout` is emitted, {@link cancelLoginAttempt} is called internally.
	 *
	 * @event
	 */
	static timeout = 'timeout';

	/**
	 * This event is emitted when Steam reports a "remote interaction" via {@link polling}. This is observed to happen
	 * when the approval prompt is viewed in the Steam mobile app for the {@link EAuthSessionGuardType.DeviceConfirmation}
	 * guard. For a {@link startWithQR | QR login}, this would be after you scan the code, but before you tap approve or deny.
	 *
	 * @event
	 */
	static remoteInteraction = 'remoteInteraction';

	/**
	 * This event is emitted when Steam sends us a new Steam Guard machine token. Machine tokens are only relevant when logging
	 * into an account that has email-based Steam Guard enabled. Thus, this will only be emitted after successfully logging into
	 * such an account.
	 *
	 * At this time, this event is only emitted when logging in using {@link EAuthTokenPlatformType.SteamClient | EAuthTokenPlatformType.SteamClient}.
	 * It's not presently possible to get a machine token for the {@link EAuthTokenPlatformType.WebBrowser} platform
	 * (and {@link EAuthTokenPlatformType.MobileApp} platform doesn't support machine tokens at all).
	 *
	 * When this event is emitted, the {@link LoginSession#steamGuardMachineToken} property contains your new machine token.
	 *
	 * @event
	 */
	static steamGuardMachineToken = 'steamGuardMachineToken';

	/**
	 * This event is emitted when we successfully authenticate with Steam. At this point, {@link accountName}
	 * and {@link refreshToken} are populated. If the {@link EAuthTokenPlatformType}
	 * passed to the {@link constructor} is appropriate, you can now safely call {@link getWebCookies}.
	 *
	 * @event
	 */
	static authenticated = 'authenticated';

	/**
	 * This event is emitted if we encounter an error while {@link polling}. The first argument to the event handler is
	 * an Error object. If this happens, the login attempt has failed and will need to be retried.
	 *
	 * Node.js will crash if this event is emitted and not handled.
	 *
	 * ```js
	 * session.on('error', (err) => {
	 *     console.error(`An error occurred: ${err.message}`);
	 * });
	 * ```
	 *
	 * @event
	 */
	static error = 'error';
}

/**
 * @param {Promise[]} promises
 * @returns {Promise}
 */
function promiseAny(promises): Promise<any> {
	// for node <15 compat
	return new Promise((resolve, reject) => {
		let pendingPromises = promises.length;
		let rejections = [];
		promises.forEach((promise) => {
			promise.then((result) => {
				pendingPromises--;
				resolve(result);
			}).catch((err) => {
				pendingPromises--;
				rejections.push(err);

				if (pendingPromises == 0) {
					reject(rejections[0]);
				}
			});
		});
	});
}

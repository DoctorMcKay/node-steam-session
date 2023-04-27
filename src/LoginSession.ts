import StdLib from '@doctormckay/stdlib';
import {HttpClient} from '@doctormckay/stdlib/http';
import {randomBytes} from 'crypto';
import createDebug from 'debug';
import EventEmitter from 'events';
import HTTPS from 'https';
import {SocksProxyAgent} from 'socks-proxy-agent';
import SteamID from 'steamid';

import AuthenticationClient from './AuthenticationClient';
import {API_HEADERS, decodeJwt, eresultError} from './helpers';

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

export default class LoginSession extends EventEmitter {
	_loginTimeout: number;

	_accountName?: string;
	_accessToken?: string;
	_refreshToken?: string;

	_platformType: EAuthTokenPlatformType;
	_webClient: HttpClient;
	_handler: AuthenticationClient;

	_steamGuardCode?: string;
	_steamGuardMachineToken?: string;
	_startSessionResponse?: StartAuthSessionResponse;
	_hadRemoteInteraction?: boolean;

	_pollingStartedTime?: number;
	_pollTimer?: Timeout;
	_pollingCanceled?: boolean;

	/**
	 * @param {EAuthTokenPlatformType} platformType
	 * @param {ConstructorOptions} [options]
	 */
	constructor(platformType: EAuthTokenPlatformType, options?: ConstructorOptions) {
		super();

		options = options || {};

		let agent:HTTPS.Agent = new HTTPS.Agent({keepAlive: true});
		if (options.httpProxy && options.socksProxy) {
			throw new Error('Cannot specify both httpProxy and socksProxy at the same time');
		}

		if (options.httpProxy) {
			agent = StdLib.HTTP.getProxyAgent(true, options.httpProxy) as HTTPS.Agent;
		} else if (options.socksProxy) {
			agent = new SocksProxyAgent(options.socksProxy);
		}

		this._webClient = new HttpClient({httpsAgent: agent});

		this._platformType = platformType;

		let transport = options.transport;
		if (!transport) {
			switch (platformType) {
				case EAuthTokenPlatformType.SteamClient:
					transport = new WebSocketCMTransport(this._webClient, agent);
					break;

				default:
					transport = new WebApiTransport(this._webClient);
			}
		}

		this._handler = new AuthenticationClient(this._platformType, transport, this._webClient);
		this._handler.on('debug', (...args) => this.emit('debug-handler', ...args));
		this.on('debug', debug);

		this.loginTimeout = 30000;
	}

	get loginTimeout(): number {
		return this._loginTimeout;
	}

	set loginTimeout(value: number) {
		if (this._pollingStartedTime) {
			throw new Error('Setting loginTimeout after polling has already started is ineffective');
		}

		this._loginTimeout = value;
	}

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

	get accountName(): string { return this._accountName; }

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
	}

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

	get steamGuardMachineToken(): string { return this._steamGuardMachineToken; }

	get _defaultWebsiteId() {
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

	_verifyStarted(mustHaveSteamId = false) {
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

	async startWithQR(): Promise<StartSessionResponse> {
		if (this._startSessionResponse) {
			throw new Error('A session has already been started on this LoginSession object. Create a new LoginSession to start a new session.');
		}

		this._hadRemoteInteraction = false;

		this._startSessionResponse = await this._handler.startSessionWithQR({
			platformType: this._platformType
		});

		this.emit('debug', 'start qr session response', this._startSessionResponse);

		return await this._processStartSessionResponse();
	}

	async _processStartSessionResponse(): Promise<StartSessionResponse> {
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

	forcePoll() {
		this._verifyStarted();

		if (!this._pollingStartedTime) {
			throw new Error('Polling has not yet started');
		}

		this._doPoll();
	}

	async _doPoll() {
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

		if (pollResponse.accessToken) {
			this._accountName = pollResponse.accountName;
			this.accessToken = pollResponse.accessToken;
			this.refreshToken = pollResponse.refreshToken;
			this.emit('authenticated');
			this.cancelLoginAttempt();
		} else if (!this._pollingCanceled) {
			this._pollTimer = setTimeout(() => this._doPoll(), this._startSessionResponse.pollInterval * 1000);
		}
	}

	/**
	 * @returns {boolean} - true if code submitted successfully, false if code wasn't valid or no code available
	 */
	async _attemptEmailCodeAuth(): Promise<boolean> {
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

	async _attemptTotpCodeAuth(): Promise<boolean> {
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

	cancelLoginAttempt(): boolean {
		this._pollingCanceled = true;
		this._handler.close();

		if (this._pollTimer) {
			clearTimeout(this._pollTimer);
			return true;
		}

		return false;
	}

	async getWebCookies(): Promise<string[]> {
		if (!this.refreshToken) {
			throw new Error('A refresh token is required to get web cookies');
		}

		let body = {
			nonce: this.refreshToken,
			sessionid: randomBytes(12).toString('hex'),
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

			let result = await this._webClient.request({
				method: 'POST',
				url,
				multipartForm: HttpClient.simpleObjectToMultipartForm(body)
			});
			if (!result.headers || !result.headers['set-cookie'] || result.headers['set-cookie'].length == 0) {
				return reject(new Error('No Set-Cookie header in result'));
			}

			if (!result.headers['set-cookie'].some(c => c.startsWith('steamLoginSecure='))) {
				return reject(new Error('No steamLoginSecure cookie in result'));
			}

			resolve(result.headers['set-cookie'].map(c => c.split(';')[0].trim()));
		}));

		return await promiseAny(transfers);
	}

	async refreshAccessToken(): Promise<void> {
		if (!this.refreshToken) {
			throw new Error('A refresh token is required to get a new access token');
		}

		this.accessToken = await this._handler.generateAccessTokenForApp(this.refreshToken);
	}
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

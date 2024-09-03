import {createHmac} from 'crypto';
import HTTPS from 'https';
import {SocksProxyAgent} from 'socks-proxy-agent';
import StdLib from '@doctormckay/stdlib';
import {HttpClient} from '@doctormckay/stdlib/http';
import SteamID from 'steamid';

import AuthenticationClient from './AuthenticationClient';
import WebApiTransport from './transports/WebApiTransport';
import {ApproveAuthSessionRequest, AuthSessionInfo, ConstructorOptions} from './interfaces-external';
import {decodeJwt, defaultUserAgent} from './helpers';
import ESessionPersistence from './enums-steam/ESessionPersistence';
import EAuthTokenPlatformType from './enums-steam/EAuthTokenPlatformType';

/**
 * Using CommonJS:
 * ```js
 * const {LoginApprover} = require('steam-session');
 * ```
 *
 * Using ES6 modules:
 * ```js
 * import {LoginSession} from 'steam-session';
 * ```
 *
 * The {@link LoginApprover} class can be used to approve a login attempt that was started with a QR code.
 *
 * @see Example: [approve-qr.ts](https://github.com/DoctorMcKay/node-steam-session/blob/master/examples/approve-qr.ts)
 */
export default class LoginApprover {
	/**
	 * A `string` or `Buffer` containing your shared secret. This is automatically set by the {@link constructor}, but
	 * you can also manually assign it if you need to set a new shared secret for some reason.
	 *
	 * If this is a `string`, it must be either hex- or base64-encoded.
	 */
	sharedSecret: string|Buffer;

	private _accessToken: string;

	private _webClient: HttpClient;
	private _handler: AuthenticationClient;

	/**
	 *
	 * @param {string} accessToken - A valid access token for the account you want to approve logins for. This access token
	 * **(not refresh token)** must have been created using the {@link EAuthTokenPlatformType.MobileApp} platform type.
	 * @param {string|Buffer} sharedSecret - Your account's TOTP shared secret. If this is a string, it must be hex- or
	 * base64-encoded.
	 * @param {ConstructorOptions} [options]
	 * @return
	 *
	 * Constructs a new `LoginApprover` instance. Example usage:
	 *
	 * ```js
	 * import {LoginApprover} from 'steam-session';
	 *
	 * let approver = new LoginApprover('eyAid...', 'oTVMfZJ9uHXo3m9MwTD9IOEWQaw=');
	 * ```
	 *
	 * An `Error` will be thrown if your `accessToken` isn't a well-formed JWT, if it's a refresh token rather than an
	 * access token, or if it's an access token that was not generated using
	 * {@link EAuthTokenPlatformType.MobileApp | EAuthTokenPlatformType.MobileApp}.
	 */
	constructor(accessToken: string, sharedSecret: string|Buffer, options?: ConstructorOptions) {
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

		this.accessToken = accessToken;
		this.sharedSecret = sharedSecret;
		this._handler = new AuthenticationClient({
			platformType: EAuthTokenPlatformType.MobileApp,
			transport: options.transport || new WebApiTransport(this._webClient),
			webClient: this._webClient,
			webUserAgent: defaultUserAgent()
		});
	}

	/**
	 * **Read-only.** A [SteamID](https://www.npmjs.com/package/steamid) instance containing the SteamID for the account
	 * to which the provided {@link accessToken} belongs. Populated immediately after {@link accessToken} is set.
	 */
	get steamID(): SteamID {
		if (this.accessToken) {
			let decodedToken = decodeJwt(this.accessToken);
			return new SteamID(decodedToken.sub);
		} else {
			return null;
		}
	}

	/**
	 * A `string` containing your access token. This is automatically set by the constructor, but you can also manually
	 * assign it if you need to set a new access token.
	 *
	 * An `Error` will be thrown when you set this property if you set it to a valid that isn't a well-formed JWT, if
	 * it's a refresh token rather than an access token, or if it's an access token that was not generated using
	 * {@link EAuthTokenPlatformType.MobileApp | EAuthTokenPlatformType.MobileApp}.
	 */
	get accessToken(): string { return this._accessToken; }
	set accessToken(token: string) {
		let decoded = decodeJwt(token);
		let aud = decoded.aud || [];

		// Is it an access token and not a refresh token?
		if (aud.includes('derive')) {
			throw new Error('Provided token is a refresh token, not an access token');
		}

		if (!aud.includes('mobile')) {
			throw new Error('Provided token is not valid for MobileApp platform usage');
		}

		this._accessToken = token;
	}

	private get _secretAsBuffer() {
		if (Buffer.isBuffer(this.sharedSecret)) {
			return this.sharedSecret;
		}

		if (this.sharedSecret.match(/^[0-9a-f]{40}$/i)) {
			// Looks like it's hex
			return Buffer.from(this.sharedSecret, 'hex');
		}

		// It must be base64
		return Buffer.from(this.sharedSecret, 'base64');
	}

	/**
	 * @param {string} qrChallengeUrl - The QR challenge URL from a {@link steam-session.LoginSession.startWithQR} call
	 * @return
	 *
	 * Retrieves info for an auth session given a QR challenge URL. Once you call this,
	 * {@link steam-session.LoginSession.remoteInteraction} will be emitted. If the QR auth session was initiated within
	 * a legitimate Steam client or website, a loading indicator will be overlayed on the QR code to indicate that the
	 * session is being dealt with on a mobile device.
	 */
	async getAuthSessionInfo(qrChallengeUrl: string): Promise<AuthSessionInfo> {
		let {clientId} = decodeQrUrl(qrChallengeUrl);
		let result = await this._handler.getAuthSessionInfo(this._accessToken, {clientId});

		return {
			ip: result.ip,
			location: {
				geoloc: result.geoloc,
				city: result.city,
				state: result.state
			},
			platformType: result.platformType,
			deviceFriendlyName: result.deviceFriendlyName,
			version: result.version,
			loginHistory: result.loginHistory,
			locationMismatch: result.locationMismatch,
			highUsageLogin: result.highUsageLogin,
			requestedPersistence: result.requestedPersistence
		};
	}

	/**
	 * @param {ApproveAuthSessionRequest} details
	 * @return
	 *
	 * Approves or denies an auth session from a QR URL. If you pass `true` for
	 * {@link method-params.ApproveAuthSessionRequest.approve}, then the next poll from the {@link steam-session.LoginSession}
	 * will return access tokens. If you pass `false`, then the {@link steam-session.LoginSession} will emit an
	 * {@link steam-session.LoginSession.error} event with EResult {@link EResult.FileNotFound}.
	 *
	 * Returns a Promise which resolves with no value. Once this Promise resolves, you could call
	 * {@link steam-session.LoginSession.forcePoll}, and the {@link steam-session.LoginSession} should then immediately
	 * emit {@link steam-session.LoginSession.authenticated}.
	 */
	async approveAuthSession(details: ApproveAuthSessionRequest): Promise<void> {
		let {clientId, version} = decodeQrUrl(details.qrChallengeUrl);

		let signatureData = Buffer.alloc(2 + 8 + 8);
		signatureData.writeUInt16LE(version, 0);
		signatureData.writeBigUInt64LE(BigInt(clientId), 2);
		signatureData.writeBigUInt64LE(BigInt(this.steamID.toString()), 10);

		let signature = createHmac('sha256', this._secretAsBuffer)
			.update(signatureData)
			.digest();

		await this._handler.submitMobileConfirmation(this.accessToken, {
			version,
			clientId,
			steamId: this.steamID.getSteamID64(),
			signature,
			confirm: details.approve,
			persistence: details.persistence || ESessionPersistence.Persistent
		});
	}
}

function decodeQrUrl(qrUrl: string): {clientId: string, version: number} {
	let match = qrUrl.match(/^https?:\/\/s\.team\/q\/(\d+)\/(\d+)(\?|$)/);
	if (!match) {
		throw new Error('Invalid QR code URL');
	}

	return {clientId: match[2], version: parseInt(match[1], 10)};
}

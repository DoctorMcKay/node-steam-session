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

export default class LoginApprover {
	private _accessToken: string;
	sharedSecret: string|Buffer;

	private _webClient: HttpClient;
	private _handler: AuthenticationClient;

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

	get steamID(): SteamID {
		if (this.accessToken) {
			let decodedToken = decodeJwt(this.accessToken);
			return new SteamID(decodedToken.sub);
		} else {
			return null;
		}
	}

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

	async approveAuthSession(details: ApproveAuthSessionRequest): Promise<void> {
		let {clientId, version} = decodeQrUrl(details.qrChallengeUrl);

		let signatureData = Buffer.alloc(2 + 8 + 8);
		signatureData.writeUInt16LE(version, 0);
		signatureData.writeBigUInt64LE(BigInt(clientId), 2);
		signatureData.writeBigUInt64LE(BigInt(this.steamID), 10);

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

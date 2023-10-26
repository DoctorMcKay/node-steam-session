import {HttpClient} from '@doctormckay/stdlib/http';
import createDebug from 'debug';
import {EventEmitter} from 'events';
import {hex2b64, Key as RSAKey} from 'node-bignumber';
import {stringify as encodeQueryString} from 'querystring';
import {clearTimeout} from 'timers';

import EAuthTokenPlatformType from './enums-steam/EAuthTokenPlatformType';
import EOSType from './enums-steam/EOSType';
import EResult from './enums-steam/EResult';
import ESessionPersistence from './enums-steam/ESessionPersistence';
import ETokenRenewalType from './enums-steam/ETokenRenewalType';

import {getProtoForMethod} from './protobufs';
import ITransport, {ApiResponse} from './transports/ITransport';

import {
	API_HEADERS,
	createMachineId,
	decodeJwt,
	eresultError,
	getSpoofedHostname,
	isJwtValidForAudience
} from './helpers';
import {
	CAuthentication_AccessToken_GenerateForApp_Request,
	CAuthentication_AccessToken_GenerateForApp_Response,
	CAuthentication_BeginAuthSessionViaCredentials_Request_BinaryGuardData,
	CAuthentication_BeginAuthSessionViaCredentials_Response,
	CAuthentication_BeginAuthSessionViaQR_Request,
	CAuthentication_BeginAuthSessionViaQR_Response,
	CAuthentication_GetAuthSessionInfo_Request,
	CAuthentication_GetAuthSessionInfo_Response,
	CAuthentication_GetPasswordRSAPublicKey_Response,
	CAuthentication_PollAuthSessionStatus_Request,
	CAuthentication_PollAuthSessionStatus_Response,
	CAuthentication_UpdateAuthSessionWithMobileConfirmation_Request,
	CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request
} from './protobuf-generated/types';
import {
	AuthenticationClientConstructorOptions,
	CheckMachineAuthRequest,
	CheckMachineAuthResponse,
	GetAuthSessionInfoRequest,
	GetAuthSessionInfoResponse,
	MobileConfirmationRequest,
	PlatformData,
	PollLoginStatusRequest,
	PollLoginStatusResponse,
	StartAuthSessionWithCredentialsRequest,
	StartAuthSessionWithCredentialsResponse,
	StartAuthSessionWithQrResponse,
	SubmitSteamGuardCodeRequest
} from './interfaces-internal';

const debug = createDebug('steam-session:AuthenticationClient');

interface RequestDefinition {
	apiInterface: string;
	apiMethod: string;
	apiVersion: number;
	data: any;
	accessToken?: string;
}

export default class AuthenticationClient extends EventEmitter {
	_transport: ITransport;
	_platformType: EAuthTokenPlatformType;
	_webClient: HttpClient;
	_transportCloseTimeout: NodeJS.Timeout;
	_webUserAgent: string;
	_machineId?: Buffer|boolean;

	constructor(options: AuthenticationClientConstructorOptions) {
		super();
		this._transport = options.transport;
		this._platformType = options.platformType;
		this._webClient = options.webClient;

		this._webUserAgent = options.webUserAgent;
		if (this._platformType == EAuthTokenPlatformType.WebBrowser) {
			this._webClient.userAgent = options.webUserAgent;
		}

		this._machineId = options.machineId;
	}

	async getRsaKey(accountName: string): Promise<CAuthentication_GetPasswordRSAPublicKey_Response> {
		return await this.sendRequest({
			apiInterface: 'Authentication',
			apiMethod: 'GetPasswordRSAPublicKey',
			apiVersion: 1,
			data: {account_name: accountName}
		});
	}

	async encryptPassword(accountName: string, password: string): Promise<{encryptedPassword: string, keyTimestamp: string}> {
		let rsaInfo = await this.getRsaKey(accountName);

		let key = new RSAKey();
		key.setPublic(rsaInfo.publickey_mod, rsaInfo.publickey_exp);

		return {
			encryptedPassword: hex2b64(key.encrypt(password)),
			keyTimestamp: rsaInfo.timestamp
		};
	}

	async startSessionWithCredentials(details: StartAuthSessionWithCredentialsRequest): Promise<StartAuthSessionWithCredentialsResponse> {
		let {websiteId, deviceDetails} = this._getPlatformData();

		let data:CAuthentication_BeginAuthSessionViaCredentials_Request_BinaryGuardData = {
			account_name: details.accountName,
			encrypted_password: details.encryptedPassword,
			encryption_timestamp: details.keyTimestamp,
			remember_login: details.persistence == ESessionPersistence.Persistent,
			persistence: details.persistence,
			website_id: websiteId,
			device_details: deviceDetails
		};

		if (details.platformType == EAuthTokenPlatformType.SteamClient) {
			// For SteamClient logins, we also need a machine id
			if (this._machineId && Buffer.isBuffer(this._machineId)) {
				data.device_details.machine_id = this._machineId;
			} else if (this._machineId === true) {
				data.device_details.machine_id = createMachineId(details.accountName);
			}
		}

		if (details.steamGuardMachineToken) {
			if (Buffer.isBuffer(details.steamGuardMachineToken)) {
				data.guard_data = details.steamGuardMachineToken;
			} else if (typeof details.steamGuardMachineToken == 'string' && isJwtValidForAudience(details.steamGuardMachineToken, 'machine')) {
				data.guard_data = Buffer.from(details.steamGuardMachineToken, 'utf8');
			}
		}

		let result:CAuthentication_BeginAuthSessionViaCredentials_Response = await this.sendRequest({
			apiInterface: 'Authentication',
			apiMethod: 'BeginAuthSessionViaCredentials',
			apiVersion: 1,
			data
		});

		return {
			clientId: result.client_id,
			requestId: result.request_id,
			pollInterval: result.interval,
			allowedConfirmations: result.allowed_confirmations.map(c => ({type: c.confirmation_type, message: c.associated_message})),
			steamId: result.steamid,
			weakToken: result.weak_token
		};
	}

	async startSessionWithQR(): Promise<StartAuthSessionWithQrResponse> {
		let {deviceDetails} = this._getPlatformData();

		let data:CAuthentication_BeginAuthSessionViaQR_Request = {
			device_details: deviceDetails
		};

		let result:CAuthentication_BeginAuthSessionViaQR_Response = await this.sendRequest({
			apiInterface: 'Authentication',
			apiMethod: 'BeginAuthSessionViaQR',
			apiVersion: 1,
			data
		});

		return {
			clientId: result.client_id,
			requestId: result.request_id,
			pollInterval: result.interval,
			allowedConfirmations: result.allowed_confirmations.map(c => ({type: c.confirmation_type, message: c.associated_message})),
			challengeUrl: result.challenge_url,
			version: result.version
		};
	}

	async submitSteamGuardCode(details: SubmitSteamGuardCodeRequest): Promise<void> {
		let data:CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request = {
			client_id: details.clientId,
			steamid: details.steamId,
			code: details.authCode,
			code_type: details.authCodeType
		};

		await this.sendRequest({
			apiInterface: 'Authentication',
			apiMethod: 'UpdateAuthSessionWithSteamGuardCode',
			apiVersion: 1,
			data
		});
	}

	async checkMachineAuthOrSendCodeEmail(details: CheckMachineAuthRequest): Promise<CheckMachineAuthResponse> {
		let headers:any = Object.assign({'content-type': 'multipart/form-data'}, API_HEADERS);

		if (details.machineAuthToken) {
			headers.cookie = `steamMachineAuth${details.steamId}=${details.machineAuthToken}`;
		}

		let body = {clientid: details.clientId, steamid: details.steamId};
		debug('POST https://login.steampowered.com/jwt/checkdevice %o', body);

		let result = await this._webClient.request({
			method: 'POST',
			url: 'https://login.steampowered.com/jwt/checkdevice',
			multipartForm: HttpClient.simpleObjectToMultipartForm(body),
			headers: API_HEADERS
		});
		return result.jsonBody as CheckMachineAuthResponse;
	}

	async pollLoginStatus(details: PollLoginStatusRequest): Promise<PollLoginStatusResponse> {
		let data:CAuthentication_PollAuthSessionStatus_Request = {
			client_id: details.clientId,
			request_id: details.requestId
		};

		let result:CAuthentication_PollAuthSessionStatus_Response = await this.sendRequest({
			apiInterface: 'Authentication',
			apiMethod: 'PollAuthSessionStatus',
			apiVersion: 1,
			data
		});

		return {
			newClientId: result.new_client_id,
			newChallengeUrl: result.new_challenge_url,
			refreshToken: result.refresh_token,
			accessToken: result.access_token,
			hadRemoteInteraction: result.had_remote_interaction,
			accountName: result.account_name,
			newSteamGuardMachineAuth: result.new_guard_data
		};
	}

	async getAuthSessionInfo(accessToken: string, details: GetAuthSessionInfoRequest): Promise<GetAuthSessionInfoResponse> {
		let data:CAuthentication_GetAuthSessionInfo_Request = {
			client_id: details.clientId
		};

		let result:CAuthentication_GetAuthSessionInfo_Response = await this.sendRequest({
			apiInterface: 'Authentication',
			apiMethod: 'GetAuthSessionInfo',
			apiVersion: 1,
			data,
			accessToken
		});

		return {
			ip: result.ip,
			geoloc: result.geoloc,
			city: result.city,
			state: result.state,
			platformType: result.platform_type,
			deviceFriendlyName: result.device_friendly_name,
			version: result.version,
			loginHistory: result.login_history,
			locationMismatch: result.requestor_location_mismatch,
			highUsageLogin: result.high_usage_login,
			requestedPersistence: result.requested_persistence
		};
	}

	async submitMobileConfirmation(accessToken: string, details: MobileConfirmationRequest): Promise<void> {
		let data:CAuthentication_UpdateAuthSessionWithMobileConfirmation_Request = {
			version: details.version,
			client_id: details.clientId,
			steamid: details.steamId,
			signature: details.signature,
			confirm: details.confirm,
			persistence: details.persistence
		};

		await this.sendRequest({
			apiInterface: 'Authentication',
			apiMethod: 'UpdateAuthSessionWithMobileConfirmation',
			apiVersion: 1,
			data,
			accessToken
		});
	}

	async generateAccessTokenForApp(refreshToken: string, renewRefreshToken = false): Promise<{accessToken: string, refreshToken?: string}> {
		let data:CAuthentication_AccessToken_GenerateForApp_Request = {
			refresh_token: refreshToken,
			steamid: decodeJwt(refreshToken).sub,
			renewal_type: renewRefreshToken ? ETokenRenewalType.Allow : ETokenRenewalType.None
		};

		let result:CAuthentication_AccessToken_GenerateForApp_Response = await this.sendRequest({
			apiInterface: 'Authentication',
			apiMethod: 'GenerateAccessTokenForApp',
			apiVersion: 1,
			data
		});

		// We're done with the transport
		this.close();

		return {
			accessToken: result.access_token,
			refreshToken: result.refresh_token || null
		};
	}

	async sendRequest(request: RequestDefinition): Promise<any> {
		// If a transport close is pending, cancel it
		clearTimeout(this._transportCloseTimeout);

		// Right now we really only support IAuthenticationService

		let {request: requestProto, response: responseProto} = getProtoForMethod(request.apiInterface, request.apiMethod);
		if (!requestProto || !responseProto) {
			throw new Error(`Unknown API method ${request.apiInterface}/${request.apiMethod}`);
		}

		let {headers} = this._getPlatformData();
		this.emit('debug', request.apiMethod, request.data, headers);

		let result:ApiResponse = await this._transport.sendRequest({
			apiInterface: request.apiInterface,
			apiMethod: request.apiMethod,
			apiVersion: request.apiVersion,
			requestData: requestProto.encode(request.data).finish(),
			accessToken: request.accessToken,
			headers
		});

		if (result.result != EResult.OK) {
			throw eresultError(result.result, result.errorMessage);
		}

		// We need to decode the response data, if there was any
		let responseData = result.responseData && result.responseData.length > 0 ? result.responseData : Buffer.alloc(0);
		let decodedData = responseProto.decode(responseData);
		return responseProto.toObject(decodedData, {longs: String});
	}

	close(): void {
		// We might possibly want to immediately use this transport again after we think we should close it.
		// For example, to refresh a token after we log on. So instead of closing immediately, delay by 2 seconds
		// before closing to give us time for this possibility.

		clearTimeout(this._transportCloseTimeout);
		this._transportCloseTimeout = setTimeout(() => {
			this._transport.close();
		}, 2000);
	}

	_getPlatformData(): PlatformData {
		switch (this._platformType) {
			case EAuthTokenPlatformType.SteamClient:
				let refererQuery = {
					IN_CLIENT: 'true',
					WEBSITE_ID: 'Client',
					LOCAL_HOSTNAME: getSpoofedHostname(),
					WEBAPI_BASE_URL: 'https://api.steampowered.com/',
					STORE_BASE_URL: 'https://store.steampowered.com/',
					USE_POPUPS: 'true',
					DEV_MODE: 'false',
					LANGUAGE: 'english',
					PLATFORM: 'windows',
					COUNTRY: 'US',
					LAUNCHER_TYPE: '0',
					IN_LOGIN: 'true'
				};

				return {
					websiteId: 'Unknown',
					// Headers are actually not used since this is sent over a CM connection
					headers: {
						'user-agent': 'Mozilla/5.0 (Windows; U; Windows NT 10.0; en-US; Valve Steam Client/default/1665786434; ) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36',
						origin: 'https://steamloopback.host',
						referer: 'https://steamloopback.host/index.html?' + encodeQueryString(refererQuery)
					},
					// device_details is also not sent for SteamClient logins, matching the behavior of the official client
					// in the past, the client did send these details, but not anymore
					deviceDetails: {
						device_friendly_name: refererQuery.LOCAL_HOSTNAME,
						platform_type: EAuthTokenPlatformType.SteamClient,
						os_type: EOSType.Win11,
						// EGamingDeviceType full definition is unknown, but 1 appears to be a desktop PC
						gaming_device_type: 1
					}
				};

			case EAuthTokenPlatformType.WebBrowser:
				return {
					websiteId: 'Community',
					headers: {
						'user-agent': this._webUserAgent,
						origin: 'https://steamcommunity.com',
						referer: 'https://steamcommunity.com'
					},
					// device details are sent for web logins
					deviceDetails: {
						device_friendly_name: this._webUserAgent,
						platform_type: EAuthTokenPlatformType.WebBrowser
					}
				};

			case EAuthTokenPlatformType.MobileApp:
				return {
					websiteId: 'Mobile',
					headers: {
						'user-agent': 'okhttp/3.12.12',
						cookie: 'mobileClient=android; mobileClientVersion=777777 3.0.0'
					},
					deviceDetails: {
						device_friendly_name: 'Galaxy S22',
						platform_type: EAuthTokenPlatformType.MobileApp,
						os_type: EOSType.AndroidUnknown,
						gaming_device_type: 528 // dunno
					}
				};

			default:
				let err:any = new Error('Unsupported platform type');
				err.platformType = this._platformType;
				throw err;
		}
	}
}

import createDebug from 'debug';
import {EventEmitter} from 'events';
import {hex2b64, Key as RSAKey} from 'node-bignumber';
import {HttpClient} from '@doctormckay/stdlib/http';

import EAuthTokenPlatformType from './enums-steam/EAuthTokenPlatformType';
import EResult from './enums-steam/EResult';

import {getProtoForMethod} from './protobufs';
import ITransport, {ApiResponse} from './transports/ITransport';

import {API_HEADERS, decodeJwt, eresultError, getDataForPlatformType, isJwtValidForAudience} from './helpers';
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
	CheckMachineAuthRequest,
	CheckMachineAuthResponse,
	GetAuthSessionInfoRequest,
	GetAuthSessionInfoResponse,
	MobileConfirmationRequest,
	PollLoginStatusRequest,
	PollLoginStatusResponse,
	StartAuthSessionRequest,
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

	constructor(platformType: EAuthTokenPlatformType, transport: ITransport, webClient: HttpClient) {
		super();
		this._transport = transport;
		this._platformType = platformType;
		this._webClient = webClient;
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
		let {websiteId, deviceDetails} = getDataForPlatformType(details.platformType);

		let data:CAuthentication_BeginAuthSessionViaCredentials_Request_BinaryGuardData = {
			account_name: details.accountName,
			encrypted_password: details.encryptedPassword,
			encryption_timestamp: details.keyTimestamp,
			persistence: details.persistence,
			website_id: websiteId,
			device_details: deviceDetails
		};

		if (details.platformType == EAuthTokenPlatformType.SteamClient) {
			// At least for SteamClient logins, we don't supply device_details.
			// TODO: check if this is true for other platform types
			data.device_friendly_name = deviceDetails.device_friendly_name;
			data.platform_type = deviceDetails.platform_type;
			delete data.device_details;
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

	async startSessionWithQR(details: StartAuthSessionRequest): Promise<StartAuthSessionWithQrResponse> {
		let {deviceDetails} = getDataForPlatformType(details.platformType);

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

	async generateAccessTokenForApp(refreshToken: string): Promise<string> {
		let data:CAuthentication_AccessToken_GenerateForApp_Request = {
			refresh_token: refreshToken,
			steamid: decodeJwt(refreshToken).sub
		};

		let result:CAuthentication_AccessToken_GenerateForApp_Response = await this.sendRequest({
			apiInterface: 'Authentication',
			apiMethod: 'GenerateAccessTokenForApp',
			apiVersion: 1,
			data
		});

		// We're done with the transport
		this._transport.close();

		return result.access_token;
	}

	async sendRequest(request: RequestDefinition): Promise<any> {
		// Right now we really only support IAuthenticationService

		let {request: requestProto, response: responseProto} = getProtoForMethod(request.apiInterface, request.apiMethod);
		if (!requestProto || !responseProto) {
			throw new Error(`Unknown API method ${request.apiInterface}/${request.apiMethod}`);
		}

		let {headers} = getDataForPlatformType(this._platformType);
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
		this._transport.close();
	}
}

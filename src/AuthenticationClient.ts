import {hex2b64, Key as RSAKey} from 'node-bignumber';

import Protos from './protobuf-generated/load';
import ITransport, {ApiResponse} from './transports/ITransport';
import EResult from './enums-steam/EResult';
import {API_HEADERS, eresultError} from './helpers';
import {
	CAuthentication_BeginAuthSessionViaCredentials_Request,
	CAuthentication_BeginAuthSessionViaCredentials_Response,
	CAuthentication_GetPasswordRSAPublicKey_Response, CAuthentication_PollAuthSessionStatus_Request,
	CAuthentication_PollAuthSessionStatus_Response,
	CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request
} from './protobuf-generated/types';
import {
	CheckMachineAuthRequest, CheckMachineAuthResponse, PollLoginStatusRequest, PollLoginStatusResponse,
	StartAuthSessionWithCredentialsRequest, StartAuthSessionWithCredentialsResponse,
	SubmitSteamGuardCodeRequest
} from './interfaces-internal';
import ESessionPersistence from './enums-steam/ESessionPersistence';
import axios, {AxiosRequestConfig, AxiosResponse} from 'axios';

interface RequestDefinition {
	apiInterface: string;
	apiMethod: string;
	apiVersion: number;
	data: any;
}

export default class AuthenticationClient {
	_transport: ITransport;

	constructor(transport: ITransport) {
		this._transport = transport;
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
		let data:CAuthentication_BeginAuthSessionViaCredentials_Request = {
			// TODO: use appropriate user-agent based on platform type
			device_friendly_name: details.deviceFriendlyName || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36',
			account_name: details.accountName,
			encrypted_password: details.encryptedPassword,
			encryption_timestamp: details.keyTimestamp,
			remember_login: details.persistence == ESessionPersistence.Persistent,
			platform_type: details.platformType,
			persistence: details.persistence,
			website_id: details.websiteId
		};

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

		let requestOptions:AxiosRequestConfig = {
			method: 'POST',
			url: 'https://login.steampowered.com/jwt/checkdevice',
			data: {
				clientid: details.clientId,
				steamid: details.steamId
			},
			headers
		};

		let result:AxiosResponse = await axios(requestOptions);
		return result.data;
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
			accountName: result.account_name
		};
	}

	async sendRequest(request: RequestDefinition): Promise<any> {
		// Right now we really only support IAuthenticationService

		let requestProto:any = Protos[`C${request.apiInterface}_${request.apiMethod}_Request`];
		let responseProto:any = Protos[`C${request.apiInterface}_${request.apiMethod}_Response`];

		if (!requestProto || !responseProto) {
			throw new Error(`Unknown API method ${request.apiInterface}/${request.apiMethod}`);
		}

		let result:ApiResponse = await this._transport.sendRequest({
			apiInterface: request.apiInterface,
			apiMethod: request.apiMethod,
			apiVersion: request.apiVersion,
			requestData: requestProto.encode(request.data).finish()
		});

		if (result.result != EResult.OK) {
			throw eresultError(result.result, result.errorMessage);
		}

		// We need to decode the response data, if there was any
		let responseData = result.responseData && result.responseData.length > 0 ? result.responseData : Buffer.alloc(0);
		let decodedData = responseProto.decode(responseData);
		return responseProto.toObject(decodedData, {longs: String});
	}
}

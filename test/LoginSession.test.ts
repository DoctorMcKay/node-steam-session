import {randomBytes} from 'crypto';
import {describe, expect, test} from '@jest/globals';
import {b64tohex, Key as RSAKey} from 'node-bignumber';
import {getAuthCode} from 'steam-totp';

import TestTransport, {DONT_CHECK_PROPERTY} from './src/TestTransport';
import {
	ApiRequest,
	ApiResponse,
	EAuthSessionGuardType,
	EAuthTokenPlatformType,
	EResult,
	ESessionPersistence,
	LoginSession
} from '../src';
import {createTokenPair, protobufDecodeRequest} from './src/helpers';
import {getSpoofedHostname} from '../src/helpers';
import {
	CAuthentication_BeginAuthSessionViaCredentials_Request_BinaryGuardData,
	CAuthentication_BeginAuthSessionViaCredentials_Response,
	CAuthentication_GetPasswordRSAPublicKey_Response,
	CAuthentication_PollAuthSessionStatus_Response
} from '../src/protobuf-generated/types';

describe('LoginSession tests', () => {
	test('full LoginSession flow', async () => {
		const LOGIN_USERNAME = 'johndoe';
		const LOGIN_PASSWORD = 'h3ll0wor1d';
		const LOGIN_SECRET = 'yOB5SANb8YqPSve2zewGeWucwUI=';
		const LOGIN_STEAMID = '76561198110478321';
		const RSAKEY_TIMESTAMP = Date.now().toString();

		const TOKEN_SET = createTokenPair(LOGIN_STEAMID, ['client', 'web']);

		let sessionClientId = randomBytes(8).readBigUInt64BE(0).toString();
		let sessionRequestId = randomBytes(16);

		let transport = new TestTransport();
		let session = new LoginSession(EAuthTokenPlatformType.SteamClient, {transport});

		let rsaKey = new RSAKey();
		rsaKey.generate(1024, (0b010001).toString(16));

		let hasSubmittedCode = false;

		transport.responder = (request: ApiRequest): ApiResponse => {
			let decodedRequest:object = protobufDecodeRequest(request);

			let requestSignature = `${request.apiInterface}.${request.apiMethod}#${request.apiVersion}`;
			switch (requestSignature) {
				case 'Authentication.GetPasswordRSAPublicKey#1':
					expect(decodedRequest).toMatchObject({account_name: LOGIN_USERNAME});

					let rsaKeyData:CAuthentication_GetPasswordRSAPublicKey_Response = {
						publickey_mod: rsaKey.n.toString(16),
						publickey_exp: rsaKey.e.toString(16),
						timestamp: RSAKEY_TIMESTAMP
					};

					return {
						result: EResult.OK,
						responseData: rsaKeyData
					};

				case 'Authentication.BeginAuthSessionViaCredentials#1':
					let req = decodedRequest as CAuthentication_BeginAuthSessionViaCredentials_Request_BinaryGuardData;
					let encryptedPassword = req.encrypted_password;
					delete req.encrypted_password;

					expect(req).toMatchObject({
						account_name: LOGIN_USERNAME,
						encryption_timestamp: RSAKEY_TIMESTAMP,
						persistence: ESessionPersistence.Persistent,
						website_id: 'Unknown'
					});

					expect(req.device_details).toMatchObject({
						device_friendly_name: getSpoofedHostname(),
						platform_type: EAuthTokenPlatformType.SteamClient,
						os_type: 20,
						gaming_device_type: 1
					});

					let decryptedPassword = rsaKey.decrypt(b64tohex(encryptedPassword)).toString('utf8');
					expect(decryptedPassword).toMatch(LOGIN_PASSWORD);

					let beginSessionData:CAuthentication_BeginAuthSessionViaCredentials_Response = {
						client_id: sessionClientId,
						request_id: sessionRequestId,
						interval: 5.0,
						allowed_confirmations: [
							{
								confirmation_type: EAuthSessionGuardType.DeviceConfirmation,
							},
							{
								confirmation_type: EAuthSessionGuardType.DeviceCode
							}
						],
						steamid: LOGIN_STEAMID
					};

					return {
						result: EResult.OK,
						responseData: beginSessionData
					};

				case 'Authentication.PollAuthSessionStatus#1':
					expect(decodedRequest).toMatchObject({
						client_id: sessionClientId,
						request_id: sessionRequestId
					});

					sessionClientId = randomBytes(8).readBigUInt64BE(0).toString();

					let pollStatusData:CAuthentication_PollAuthSessionStatus_Response = {
						new_client_id: sessionClientId,
						had_remote_interaction: false,
					};

					if (hasSubmittedCode) {
						pollStatusData = {
							refresh_token: TOKEN_SET.refreshToken,
							access_token: TOKEN_SET.accessToken,
							account_name: LOGIN_USERNAME,
							new_guard_data: TOKEN_SET.guardData,
							...pollStatusData
						};
					}

					return {
						result: EResult.OK,
						responseData: pollStatusData
					};

				case 'Authentication.UpdateAuthSessionWithSteamGuardCode#1':
					expect(decodedRequest).toMatchObject({
						client_id: sessionClientId,
						steamid: LOGIN_STEAMID,
						code: getAuthCode(LOGIN_SECRET),
						code_type: EAuthSessionGuardType.DeviceCode
					});

					return {result: EResult.OK};

				default:
					console.error(`Unhandled request ${requestSignature}`);
					expect(false).toBeTruthy();
			}
		};

		// Events that we expect to be emitted
		let emittedEvents = {
			polling: false,
			timeout: false,
			remoteInteraction: false,
			steamGuardMachineToken: false,
			authenticated: false,
			error: false
		};

		// we need a promise for jest to wait on
		let finishPromise:Promise<void> = new Promise((resolve, reject) => {
			session.on('polling', () => emittedEvents.polling = true);
			session.on('timeout', () => emittedEvents.timeout = true);
			session.on('remoteInteraction', () => emittedEvents.remoteInteraction = true);
			session.on('steamGuardMachineToken', () => emittedEvents.steamGuardMachineToken = true);
			session.on('authenticated', () => {
				emittedEvents.authenticated = true;
				resolve();
			});
			session.on('error', (err) => {
				emittedEvents.error = true;
				reject(err);
			});
		});

		let sessionStartResult = await session.startWithCredentials({
			accountName: LOGIN_USERNAME,
			password: LOGIN_PASSWORD
		});

		expect(transport.requestWasMade({
			apiInterface: 'Authentication',
			apiMethod: 'GetPasswordRSAPublicKey',
			apiVersion: 1,
			requestData: {account_name: LOGIN_USERNAME}
		})).toBeTruthy();

		expect(transport.requestWasMade({
			apiInterface: 'Authentication',
			apiMethod: 'BeginAuthSessionViaCredentials',
			apiVersion: 1,
			requestData: {
				account_name: LOGIN_USERNAME,
				encrypted_password: DONT_CHECK_PROPERTY,
				encryption_timestamp: RSAKEY_TIMESTAMP,
				persistence: ESessionPersistence.Persistent,
				remember_login: true,
				website_id: 'Unknown',
				device_details: {
					device_friendly_name: getSpoofedHostname(),
					platform_type: EAuthTokenPlatformType.SteamClient,
					os_type: 20,
					gaming_device_type: 1,
					machine_id: DONT_CHECK_PROPERTY
				}
			}
		})).toBeTruthy();

		expect(sessionStartResult).toMatchObject({
			actionRequired: true,
			validActions: [
				{
					type: EAuthSessionGuardType.DeviceConfirmation
				},
				{
					type: EAuthSessionGuardType.DeviceCode
				}
			]
		});

		// delay 100ms to allow the first poll to finish
		await new Promise(resolve => setTimeout(resolve, 100));

		await session.submitSteamGuardCode(getAuthCode(LOGIN_SECRET));
		hasSubmittedCode = true;

		expect(transport.requestWasMade({
			apiInterface: 'Authentication',
			apiMethod: 'UpdateAuthSessionWithSteamGuardCode',
			apiVersion: 1,
			requestData: {
				client_id: sessionClientId,
				steamid: LOGIN_STEAMID,
				code: getAuthCode(LOGIN_SECRET),
				code_type: EAuthSessionGuardType.DeviceCode
			}
		})).toBeTruthy();

		await finishPromise;

		expect(emittedEvents).toMatchObject({
			polling: true,
			timeout: false,
			remoteInteraction: false,
			steamGuardMachineToken: true,
			authenticated: true,
			error: false
		});

		expect(session.accountName).toMatch(LOGIN_USERNAME);
		expect(session.accessToken).toBeNull();
		expect(session.refreshToken).toMatch(TOKEN_SET.refreshToken);
		expect(session.steamGuardMachineToken).toMatch(TOKEN_SET.guardData);
	});
});

process.on('unhandledRejection', (err) => {
	throw err;
});

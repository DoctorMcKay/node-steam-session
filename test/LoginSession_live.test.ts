import {describe, expect, jest, test} from '@jest/globals';
import {getAuthCode} from 'steam-totp';

import {EAuthSessionGuardType, EAuthTokenPlatformType, LoginSession} from '../src';
import {decodeJwt} from '../src/helpers';

let liveTestDescribe = process.env.LOGIN_SESSION_LIVE_TEST_DATA ? describe : describe.skip;

liveTestDescribe('LoginSession live tests', () => {
	describe('mobile 2FA logins', () => {
		let accountDetails = JSON.parse(process.env.LOGIN_SESSION_LIVE_TEST_DATA || '[{"nickname":"Skipped due to no test data"}]');
		accountDetails.forEach((account) => {
			describe(account.nickname, () => {
				test('EAuthTokenPlatformType.SteamClient', () => new Promise(async (resolve, reject) => {
					jest.setTimeout(20000);

					let session = new LoginSession(EAuthTokenPlatformType.SteamClient);

					session.on('error', reject);
					session.on('polling', () => console.log('Polling started'));
					session.on('timeout', () => reject(new Error('Login session timed out')));

					let startResult = await session.startWithCredentials({
						accountName: account.accountName,
						password: account.password
					});

					if (!startResult.validActions.some(a => a.type == EAuthSessionGuardType.DeviceCode)) {
						return reject(new Error('DeviceCode is not a valid action'));
					}

					// Use -35 second offset so we get 3 different codes for our 3 different tests.
					// The backend should accept +/- 1 code.
					await session.submitSteamGuardCode(getAuthCode(account.sharedSecret, -35));

					session.on('authenticated', async () => {
						// 2023-09-12: no access token is present in this response anymore
						//expect(typeof session.accessToken).toBe('string');
						expect(typeof session.refreshToken).toBe('string');

						let decodedRefreshToken = decodeJwt(session.refreshToken);
						expect(decodedRefreshToken.aud).toContain('client');
						expect(decodedRefreshToken.aud).toContain('web');
						expect(decodedRefreshToken.aud).toContain('renew');
						expect(decodedRefreshToken.aud).toContain('derive');
						expect(decodedRefreshToken.sub).toBe(account.steamId);
						expect(decodedRefreshToken.iss).toBe('steam');

						//let decodedAccessToken = decodeJwt(session.accessToken);
						//expect(decodedAccessToken.aud).toContain('client');
						//expect(decodedAccessToken.aud).toContain('web');
						//expect(decodedAccessToken.sub).toBe(account.steamId);
						//expect(decodedAccessToken.iss).toBe(`r:${decodedRefreshToken.jti}`);

						let cookies = await session.getWebCookies();
						expect(Array.isArray(cookies)).toBe(true);
						expect(cookies.length).toBeGreaterThan(0);

						// We now expect to have an access token.
						expect(typeof session.accessToken).toBe('string');
						let decodedAccessToken = decodeJwt(session.accessToken);
						expect(decodedAccessToken.aud).toContain('client');
						expect(decodedAccessToken.aud).toContain('web');
						expect(decodedAccessToken.sub).toBe(account.steamId);
						expect(decodedAccessToken.iss).toBe(`r:${decodedRefreshToken.jti}`);

						resolve(null);
					});
				}));

				test('EAuthTokenPlatformType.WebBrowser', () => new Promise(async (resolve, reject) => {
					jest.setTimeout(20000);

					let session = new LoginSession(EAuthTokenPlatformType.WebBrowser);

					session.on('error', reject);
					session.on('polling', () => console.log('Polling started'));
					session.on('timeout', () => reject(new Error('Login session timed out')));

					let startResult = await session.startWithCredentials({
						accountName: account.accountName,
						password: account.password
					});

					if (!startResult.validActions.some(a => a.type == EAuthSessionGuardType.DeviceCode)) {
						return reject(new Error('DeviceCode is not a valid action'));
					}

					await session.submitSteamGuardCode(getAuthCode(account.sharedSecret, 0));

					session.on('authenticated', async () => {
						//expect(typeof session.accessToken).toBe('string');
						expect(typeof session.refreshToken).toBe('string');

						let decodedRefreshToken = decodeJwt(session.refreshToken);
						expect(decodedRefreshToken.aud).toContain('web');
						expect(decodedRefreshToken.aud).toContain('renew');
						expect(decodedRefreshToken.aud).toContain('derive');
						expect(decodedRefreshToken.sub).toBe(account.steamId);
						expect(decodedRefreshToken.iss).toBe('steam');

						//let decodedAccessToken = decodeJwt(session.accessToken);
						//expect(decodedAccessToken.aud).toContain('web');
						//expect(decodedAccessToken.sub).toBe(account.steamId);
						//expect(decodedAccessToken.iss).toBe(`r:${decodedRefreshToken.jti}`);

						let cookies = await session.getWebCookies();
						expect(Array.isArray(cookies)).toBe(true);
						expect(cookies.length).toBeGreaterThan(0);

						resolve(null);
					});
				}));

				test('EAuthTokenPlatformType.MobileApp', () => new Promise(async (resolve, reject) => {
					jest.setTimeout(20000);

					let session = new LoginSession(EAuthTokenPlatformType.MobileApp);

					session.on('error', reject);
					session.on('polling', () => console.log('Polling started'));
					session.on('timeout', () => reject(new Error('Login session timed out')));

					let startResult = await session.startWithCredentials({
						accountName: account.accountName,
						password: account.password
					});

					if (!startResult.validActions.some(a => a.type == EAuthSessionGuardType.DeviceCode)) {
						return reject(new Error('DeviceCode is not a valid action'));
					}

					// Use -35 second offset so we get 3 different codes for our 3 different tests.
					// The backend should accept +/- 1 code.
					await session.submitSteamGuardCode(getAuthCode(account.sharedSecret, 35));

					session.on('authenticated', async () => {
						//expect(typeof session.accessToken).toBe('string');
						expect(typeof session.refreshToken).toBe('string');

						let decodedRefreshToken = decodeJwt(session.refreshToken);
						expect(decodedRefreshToken.aud).toContain('web');
						expect(decodedRefreshToken.aud).toContain('mobile');
						expect(decodedRefreshToken.aud).toContain('renew');
						expect(decodedRefreshToken.aud).toContain('derive');
						expect(decodedRefreshToken.sub).toBe(account.steamId);
						expect(decodedRefreshToken.iss).toBe('steam');

						//let decodedAccessToken = decodeJwt(session.accessToken);
						//expect(decodedAccessToken.aud).toContain('web');
						//expect(decodedAccessToken.aud).toContain('mobile');
						//expect(decodedAccessToken.sub).toBe(account.steamId);
						//expect(decodedAccessToken.iss).toBe(`r:${decodedRefreshToken.jti}`);

						let cookies = await session.getWebCookies();
						expect(Array.isArray(cookies)).toBe(true);
						expect(cookies.length).toBeGreaterThan(0);

						expect(typeof session.accessToken).toBe('string');
						let decodedAccessToken = decodeJwt(session.accessToken);
						expect(decodedAccessToken.aud).toContain('web');
						expect(decodedAccessToken.aud).toContain('mobile');
						expect(decodedAccessToken.sub).toBe(account.steamId);
						expect(decodedAccessToken.iss).toBe(`r:${decodedRefreshToken.jti}`);

						resolve(null);
					});
				}));
			});
		});
	});
});

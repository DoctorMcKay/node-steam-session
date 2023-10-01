import {createHash} from 'crypto';
import {hostname} from 'os';
import {stringify as encodeQueryString} from 'querystring';

import EResult from './enums-steam/EResult';
import EAuthTokenPlatformType from './enums-steam/EAuthTokenPlatformType';
import {PlatformData} from './interfaces-internal';
import EOSType from './enums-steam/EOSType';

const CHROME_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36';

export function eresultError(result:EResult, errorMessage?:string): Error {
	let resultMsg:string = result.toString(); // this is the numeric value, as a string
	resultMsg = EResult[resultMsg] || resultMsg; // this is now the string representation of the EResult value

	let err = new Error(errorMessage || resultMsg);
	// @ts-ignore
	err.eresult = result;
	return err;
}

export const API_HEADERS = {
	accept: 'application/json, text/plain, */*',
	'sec-fetch-site': 'cross-site',
	'sec-fetch-mode': 'cors',
	'sec-fetch-dest': 'empty'
};

export function decodeJwt(jwt:string): any {
	let parts = jwt.split('.');
	if (parts.length != 3) {
		throw new Error('Invalid JWT');
	}

	let standardBase64 = parts[1].replace(/-/g, '+')
		.replace(/_/g, '/');

	return JSON.parse(Buffer.from(standardBase64, 'base64').toString('utf8'));
}

export function isJwtValidForAudience(jwt:string, audience:string, steamId?:string): boolean {
	let decodedToken:any;
	try {
		decodedToken = decodeJwt(jwt);
	} catch (ex) {
		return false;
	}

	// Check if the steamid matches
	if (steamId && decodedToken.sub != steamId) {
		return false;
	}

	return (decodedToken.aud || []).includes(audience);
}

export function getDataForPlatformType(platformType:EAuthTokenPlatformType): PlatformData {
	switch (platformType) {
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
				websiteId: 'Client',
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
					os_type: EOSType.Windows10,
					// EGamingDeviceType full definition is unknown, but 1 appears to be a desktop PC
					gaming_device_type: 1
				}
			};

		case EAuthTokenPlatformType.WebBrowser:
			return {
				websiteId: 'Community',
				headers: {
					'user-agent': CHROME_USER_AGENT,
					origin: 'https://steamcommunity.com',
					referer: 'https://steamcommunity.com'
				},
				// device details are sent for web logins
				deviceDetails: {
					device_friendly_name: CHROME_USER_AGENT,
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
			err.platformType = platformType;
			throw err;
	}
}

export function getSpoofedHostname() {
	let hash = createHash('sha1');
	hash.update(hostname());
	let sha1 = hash.digest();

	const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

	let output = 'DESKTOP-';
	for (let i = 0; i < 7; i++) {
		output += CHARS[sha1[i] % CHARS.length];
	}

	return output;
}

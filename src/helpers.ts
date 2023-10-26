import {chrome} from '@doctormckay/user-agents';
import {createHash} from 'crypto';
import {hostname} from 'os';

import EResult from './enums-steam/EResult';

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

export function defaultUserAgent() {
	return chrome();
}

export function createMachineId(accountName: string): Buffer {
	return Buffer.concat([
		byteToBuffer(0),
		stringToBuffer('MessageObject'),

		byteToBuffer(1),
		stringToBuffer('BB3'),
		stringToBuffer(sha1(`SteamUser Hash BB3 ${accountName}`)),

		byteToBuffer(1),
		stringToBuffer('FF2'),
		stringToBuffer(sha1(`SteamUser Hash FF2 ${accountName}`)),

		byteToBuffer(1),
		stringToBuffer('3B3'),
		stringToBuffer(sha1(`SteamUser Hash 3B3 ${accountName}`)),

		byteToBuffer(8),
		byteToBuffer(8)
	]);

	function sha1(input) {
		let hash = createHash('sha1');
		hash.update(input, 'utf8');
		return hash.digest('hex');
	}

	function stringToBuffer(input) {
		let b = Buffer.from(input, 'utf8');
		return Buffer.concat([
			b,
			Buffer.from('00', 'hex')
		]);
	}

	function byteToBuffer(input) {
		let b = Buffer.alloc(1);
		b[0] = input;
		return b;
	}
}

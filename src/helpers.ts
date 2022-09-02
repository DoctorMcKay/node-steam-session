import EResult from './enums-steam/EResult';

export function eresultError(result:EResult, errorMessage?:string): Error {
	let resultMsg:string = result.toString();

	for (let i in EResult) {
		if (EResult[i] == result.toString()) {
			resultMsg = i;
			break;
		}
	}

	let err = new Error(errorMessage || resultMsg);
	// @ts-ignore
	err.eresult = result;
	return err;
}

export const API_HEADERS = {
	origin: 'https://steamcommunity.com',
	referer: 'https://steamcommunity.com/',
	accept: 'application/json, text/plain, */*'
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

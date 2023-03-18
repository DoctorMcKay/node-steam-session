import {ApiRequest} from '../../src';
import Protos from '../../src/protobuf-generated/load';
import {randomBytes} from 'crypto';

export function protobufEncodeResponse(request: ApiRequest, response: object): Buffer {
	let protoSignature = `C${request.apiInterface}_${request.apiMethod}`;
	let responseProtoSignature = `${protoSignature}_Response`;

	let proto:any = Protos[responseProtoSignature];
	return proto.encode(response).finish();
}

export function protobufEncodeRequest(request: ApiRequest, requestData: object): Buffer {
	let protoSignature = `C${request.apiInterface}_${request.apiMethod}`;
	let requestProtoSignature = `${protoSignature}_Request`;

	if (protoSignature == 'CAuthentication_BeginAuthSessionViaCredentials') {
		// we need to use our custom definition to support sentry file hashes
		requestProtoSignature += '_BinaryGuardData';
	}

	let proto:any = Protos[requestProtoSignature];
	return proto.encode(requestData);
}

export function protobufDecodeRequest(request: ApiRequest): Buffer {
	let protoSignature = `C${request.apiInterface}_${request.apiMethod}`;
	let requestProtoSignature = `${protoSignature}_Request`;

	if (protoSignature == 'CAuthentication_BeginAuthSessionViaCredentials') {
		// we need to use our custom definition to support sentry file hashes
		requestProtoSignature += '_BinaryGuardData';
	}

	let proto:any = Protos[requestProtoSignature];
	let decoded = proto.decode(request.requestData);
	return proto.toObject(decoded, {longs: String});
}

interface TokenSet {
	accessToken: string;
	refreshToken: string;
	guardData: string;
}

export function createTokenPair(steamId: string, aud: string[]): TokenSet {
	let now = Math.floor(Date.now() / 1000);
	let myIpBytes = randomBytes(4);
	let myIp = Array.prototype.slice.call(myIpBytes).join('.');

	let refreshTokenData = {
		iss: 'steam',
		sub: steamId,
		aud: [...aud, 'renew', 'derive'],
		exp: now + (60 * 60 * 24 * 200),
		nbf: now - (60 * 60 * 24 * 100),
		iat: now,
		jti: generateJti(),
		oat: now,
		per: 1,
		ip_subject: myIp,
		ip_confirmer: myIp
	};

	let accessTokenData = {
		...refreshTokenData,
		iss: `r:${refreshTokenData.jti}`,
		aud,
		jti: generateJti(),
		exp: now + (60 * 60 * 24),
		rt_exp: refreshTokenData.exp,
		per: 0
	};

	let guardData = {
		...refreshTokenData,
		iss: `r:${refreshTokenData.jti}`,
		aud: ['machine'],
		jti: generateJti(),
		rt_exp: refreshTokenData.exp,
		per: 0,
	};

	return {
		accessToken: encodeJwt(accessTokenData),
		refreshToken: encodeJwt(refreshTokenData),
		guardData: encodeJwt(guardData)
	};
}

function encodeJwt(body): string {
	let header = JSON.stringify({
		typ: 'JWT',
		alg: 'EdDSA'
	});
	let signature = randomBytes(64);

	return [
		header,
		JSON.stringify(body),
		signature
	].map(urlSafeBase64).join('.');
}

function urlSafeBase64(input: Buffer|string): string {
	if (!Buffer.isBuffer(input)) {
		input = Buffer.from(input, 'utf8');
	}

	return input.toString('base64')
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=/g, '');
}

function generateJti(): string {
	return randomBytes(9)
		.toString('hex')
		.toUpperCase()
		.replace(/^([0-9A-F]{4})([0-9A-F]{8})([0-9A-F]{5}).+$/, '$1_$2_$3');
}

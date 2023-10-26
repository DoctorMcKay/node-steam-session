import ESessionPersistence from './enums-steam/ESessionPersistence';
import EAuthTokenPlatformType from './enums-steam/EAuthTokenPlatformType';
import EAuthSessionGuardType from './enums-steam/EAuthSessionGuardType';
import EResult from './enums-steam/EResult';
import EAuthSessionSecurityHistory from './enums-steam/EAuthSessionSecurityHistory';
import {CAuthentication_DeviceDetails} from './protobuf-generated/types';
import ITransport from './transports/ITransport';
import {HttpClient} from '@doctormckay/stdlib/http';

export interface PlatformData {
	headers: any;
	websiteId: string;
	deviceDetails: CAuthentication_DeviceDetails;
}

export interface AuthenticationClientConstructorOptions {
	platformType: EAuthTokenPlatformType,
	transport: ITransport,
	webClient: HttpClient,
	webUserAgent: string,
	machineId?: Buffer|boolean
}

export interface StartAuthSessionRequest {
	platformType: EAuthTokenPlatformType;
}

export interface StartAuthSessionResponse {
	clientId: string;
	requestId: Buffer;
	pollInterval: number;
	allowedConfirmations: AllowedConfirmation[],
}

export interface StartAuthSessionWithCredentialsRequest extends StartAuthSessionRequest {
	accountName: string;
	encryptedPassword: string;
	keyTimestamp: string;
	persistence: ESessionPersistence;
	platformType: EAuthTokenPlatformType;
	steamGuardMachineToken?: string|Buffer;
}

export interface StartAuthSessionWithCredentialsResponse extends StartAuthSessionResponse {
	steamId: string;
	weakToken: string;
}

export interface StartAuthSessionWithQrResponse extends StartAuthSessionResponse {
	challengeUrl: string;
	version: number;
}

export interface AllowedConfirmation {
	type: EAuthSessionGuardType;
	message?: string;
}

export interface SubmitSteamGuardCodeRequest {
	clientId: string;
	steamId: string;
	authCode: string;
	authCodeType: EAuthSessionGuardType;
}

export interface CheckMachineAuthRequest {
	clientId: string;
	steamId: string;
	machineAuthToken?: string;
}

export interface CheckMachineAuthResponse {
	success: boolean;
	result: EResult;
}

export interface PollLoginStatusRequest {
	clientId: string;
	requestId: Buffer;
}

export interface PollLoginStatusResponse {
	newClientId?: string;
	newChallengeUrl?: string;
	refreshToken?: string;
	accessToken?: string;
	hadRemoteInteraction?: boolean;
	accountName?: string;
	newSteamGuardMachineAuth?: string;
}

export interface GetAuthSessionInfoRequest {
	clientId: string;
}

export interface GetAuthSessionInfoResponse {
	ip: string;
	geoloc: string;
	city: string;
	state: string;
	platformType: EAuthTokenPlatformType;
	deviceFriendlyName: string;
	version: number;
	loginHistory: EAuthSessionSecurityHistory;
	locationMismatch: boolean;
	highUsageLogin: boolean;
	requestedPersistence: ESessionPersistence;
}

export interface MobileConfirmationRequest {
	version: number;
	clientId: string;
	steamId: string;
	signature: Buffer;
	confirm: boolean;
	persistence: ESessionPersistence;
}

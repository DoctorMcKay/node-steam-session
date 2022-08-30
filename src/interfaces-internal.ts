import ESessionPersistence from './enums-steam/ESessionPersistence';
import EAuthTokenPlatformType from './enums-steam/EAuthTokenPlatformType';
import EAuthSessionGuardType from './enums-steam/EAuthSessionGuardType';
import EResult from './enums-steam/EResult';

export interface StartAuthSessionWithCredentialsRequest {
	deviceFriendlyName?: string;
	accountName: string;
	encryptedPassword: string;
	keyTimestamp: string;
	persistence: ESessionPersistence;
	platformType: EAuthTokenPlatformType;
	websiteId: string;
}

export interface StartAuthSessionWithCredentialsResponse {
	clientId: string;
	requestId: Buffer;
	pollInterval: number;
	allowedConfirmations: AllowedConfirmation[],
	steamId: string;
	weakToken: string;
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
}

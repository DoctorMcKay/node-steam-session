import ESessionPersistence from './enums-steam/ESessionPersistence';
import EAuthSessionGuardType from './enums-steam/EAuthSessionGuardType';
import EAuthTokenPlatformType from './enums-steam/EAuthTokenPlatformType';
import EAuthSessionSecurityHistory from './enums-steam/EAuthSessionSecurityHistory';

export interface StartLoginSessionWithCredentialsDetails {
	accountName: string;
	password: string;
	persistence?: ESessionPersistence;
	steamGuardMachineToken?: string;
	steamGuardCode?: string;
}

export interface StartLoginSessionWithQRDetails {
	deviceFriendlyName?: string;
}

export interface StartSessionResponse {
	actionRequired: boolean;
	validActions?: StartSessionResponseValidAction[];

	// The following is for QR logins
	qrChallengeUrl?: string;
}

export interface StartSessionResponseValidAction {
	type: EAuthSessionGuardType;
	detail?: string;
}

export interface AuthSessionInfo {
	ip: string;
	location: {
		geoloc: string;
		city: string;
		state: string;
	}
	platformType: EAuthTokenPlatformType;
	deviceFriendlyName: string;
	version: number;
	loginHistory: EAuthSessionSecurityHistory;
	locationMismatch: boolean;
	highUsageLogin: boolean;
	requestedPersistence: ESessionPersistence;
}

export interface ApproveAuthSessionRequest {
	qrChallengeUrl: string;
	approve: boolean;
	persistence?: ESessionPersistence;
}

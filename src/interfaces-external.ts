import ESessionPersistence from './enums-steam/ESessionPersistence';
import EAuthSessionGuardType from './enums-steam/EAuthSessionGuardType';

export interface StartLoginSessionWithCredentialsDetails {
	accountName: string;
	password: string;
	deviceFriendlyName?: string;
	persistence?: ESessionPersistence;
	websiteId?: string;
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

import EventEmitter from 'events';
import SteamID from 'steamid';

import AuthenticationClient from './AuthenticationClient';
import ITransport from './transports/ITransport';
import EAuthTokenPlatformType from './enums-steam/EAuthTokenPlatformType';
import WebApiTransport from './transports/WebApiTransport';
import {StartLoginSessionWithCredentialsDetails} from './interfaces-external';
import {CheckMachineAuthResponse, StartAuthSessionWithCredentialsResponse} from './interfaces-internal';
import ESessionPersistence from './enums-steam/ESessionPersistence';
import EAuthSessionGuardType from './enums-steam/EAuthSessionGuardType';
import EResult from './enums-steam/EResult';
import Timeout = NodeJS.Timeout;

export default class LoginSession extends EventEmitter {
	accountName?: string;
	accessToken?: string;
	refreshToken?: string;

	_platformType: EAuthTokenPlatformType;
	_handler: AuthenticationClient;

	_steamGuardCode?: string;
	_steamGuardMachineToken?: string;
	_startSessionResponse?: StartAuthSessionWithCredentialsResponse;
	_hadRemoteInteraction?: boolean;

	_pollingStartedTime?: number;
	_pollTimer?: Timeout;
	_pollingCanceled?: boolean;

	/**
	 * @param {EAuthTokenPlatformType} [platformType=WebBrowser]
	 * @param {ITransport} [transport=WebApiTransport]
	 */
	constructor(platformType?: EAuthTokenPlatformType, transport?: ITransport) {
		super();

		this._platformType = platformType || EAuthTokenPlatformType.WebBrowser;
		this._handler = new AuthenticationClient(transport || new WebApiTransport());
	}

	get steamID(): SteamID {
		if (!this._startSessionResponse) {
			return null;
		}

		return new SteamID(this._startSessionResponse.steamId);
	}

	get _defaultWebsiteId() {
		switch (this._platformType) {
			case EAuthTokenPlatformType.SteamClient:
				return '';

			case EAuthTokenPlatformType.WebBrowser:
				return 'Community';

			case EAuthTokenPlatformType.MobileApp:
				return 'MobileApp'; // TODO confirm this

			default:
				return 'Community';
		}
	}

	_verifyStarted() {
		if (!this._startSessionResponse) {
			throw new Error('Login session has not been started yet');
		}
	}

	async startWithCredentials(details: StartLoginSessionWithCredentialsDetails): Promise<void> {
		this._hadRemoteInteraction = false;
		this._steamGuardCode = details.steamGuardCode;
		this._steamGuardMachineToken = details.steamGuardMachineToken;

		let encryptionResult = await this._handler.encryptPassword(details.accountName, details.password);

		this._startSessionResponse = await this._handler.startSessionWithCredentials({
			deviceFriendlyName: details.deviceFriendlyName,
			accountName: details.accountName,
			...encryptionResult,
			persistence: details.persistence || ESessionPersistence.Persistent,
			platformType: this._platformType,
			websiteId: details.websiteId || this._defaultWebsiteId
		});

		this.emit('debug', 'start session response', this._startSessionResponse);

		// Use setImmediate so that the promise is resolved before we potentially emit a session
		setImmediate(() => this._processStartSessionResponse());
	}

	_processStartSessionResponse() {
		this._pollingCanceled = false;

		for (let i of this._startSessionResponse.allowedConfirmations) {
			switch (i.type) {
				case EAuthSessionGuardType.None:
					this.emit('debug', 'no guard required');
					this._doPoll();
					break;

				case EAuthSessionGuardType.EmailCode:
					this.emit('debug', 'email code required');
					this._attemptEmailCodeAuth();
					break;

				case EAuthSessionGuardType.DeviceCode:
					this.emit('debug', 'device code guard required');
					this._attemptTotpCodeAuth();
					break;

				case EAuthSessionGuardType.DeviceConfirmation:
				case EAuthSessionGuardType.EmailConfirmation:
					this.emit('debug', 'device or email confirmation guard required');
					this.emit('authSessionGuardRequired', i.type);
					this._doPoll();
					break;

				case EAuthSessionGuardType.MachineToken:
					break;

				default:
					let guardTypeString:string = i.type.toString();
					for (let j in EAuthSessionGuardType) {
						if (EAuthSessionGuardType[j] == guardTypeString) {
							guardTypeString = j;
							break;
						}
					}

					let err = new Error(`Unknown auth session guard type ${guardTypeString}`);
					this.emit('error', err);
			}
		}
	}

	async _doPoll() {
		if (this._pollingCanceled) {
			return;
		}

		this._pollingStartedTime = this._pollingStartedTime || Date.now();

		// TODO timeout polling

		let pollResponse;
		try {
			pollResponse = await this._handler.pollLoginStatus(this._startSessionResponse);
			this.emit('debug', 'poll response', pollResponse);
		} catch (ex) {
			this.emit('error', ex);
			return;
		}

		this._startSessionResponse.clientId = pollResponse.newClientId || this._startSessionResponse.clientId;

		if (pollResponse.hadRemoteInteraction && !this._hadRemoteInteraction) {
			this._hadRemoteInteraction = true;
			this.emit('remoteInteraction');
		}

		if (pollResponse.accessToken) {
			this.accountName = pollResponse.accountName;
			this.accessToken = pollResponse.accessToken;
			this.refreshToken = pollResponse.refreshToken;
			this.emit('authenticated');
		} else if (!this._pollingCanceled) {
			this._pollTimer = setTimeout(() => this._doPoll(), this._startSessionResponse.pollInterval * 1000);
		}
	}

	async _attemptEmailCodeAuth() {
		if (this._steamGuardCode) {
			try {
				await this.submitSteamGuardCode(this._steamGuardCode);
				return;
			} catch (ex) {
				if (ex.eresult != EResult.InvalidLoginAuthCode) {
					// this is some kind of important error
					this.emit('error', ex);
				}
			}
		}

		// Can we use a machine auth token?
		if (this._startSessionResponse.allowedConfirmations.some(c => c.type == EAuthSessionGuardType.MachineToken)) {
			let result:CheckMachineAuthResponse;
			try {
				result = await this._handler.checkMachineAuthOrSendCodeEmail({
					machineAuthToken: this._steamGuardMachineToken,
					...this._startSessionResponse
				});
			} catch (ex) {
				this.emit('error', ex);
				return;
			}

			if (result.result == EResult.OK) {
				// Machine auth succeeded
				this._doPoll();
				return;
			}
		}

		// An email was sent
		let confirmation = this._startSessionResponse.allowedConfirmations.find(c => c.type == EAuthSessionGuardType.EmailCode);
		this.emit('authSessionGuardRequired', EAuthSessionGuardType.EmailCode, {domain: confirmation.message});
	}

	async _attemptTotpCodeAuth() {
		if (this._steamGuardCode) {
			try {
				await this.submitSteamGuardCode(this._steamGuardCode);
				return; // submitting code succeeded
			} catch (ex) {
				if (ex.eresult != EResult.TwoFactorCodeMismatch) {
					// this is some kind of important error
					this.emit('error', ex);
				}
			}
		}

		// If we got here, then we need the user to supply a code
		this.emit('authSessionGuardRequired', EAuthSessionGuardType.DeviceCode);
	}

	async submitSteamGuardCode(authCode: string) {
		this._verifyStarted();

		this.emit('debug', 'submitting steam guard code', authCode);

		let needsEmailCode = this._startSessionResponse.allowedConfirmations.some(c => c.type == EAuthSessionGuardType.EmailCode);
		let needsTotpCode = this._startSessionResponse.allowedConfirmations.some(c => c.type == EAuthSessionGuardType.DeviceCode);
		if (!needsEmailCode && !needsTotpCode) {
			throw new Error('No Steam Guard code is needed for this login attempt');
		}

		await this._handler.submitSteamGuardCode({
			...this._startSessionResponse,
			authCode,
			authCodeType: needsEmailCode ? EAuthSessionGuardType.EmailCode : EAuthSessionGuardType.DeviceCode
		});

		setImmediate(() => this._doPoll());
	}

	cancelLoginAttempt(): boolean {
		this._pollingCanceled = true;

		if (this._pollTimer) {
			clearTimeout(this._pollTimer);
			return true;
		}

		return false;
	}
}

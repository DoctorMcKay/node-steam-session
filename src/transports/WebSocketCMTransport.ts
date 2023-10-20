import {randomBytes} from 'crypto';
import createDebug from 'debug';
import {Agent} from 'https';
import {Semaphore} from '@doctormckay/stdlib/concurrency';
import {TTLCache} from '@doctormckay/stdlib/data_structures';
import {HttpClient} from '@doctormckay/stdlib/http';
import VDF from 'kvparser';
import {FrameType as WsFrameType, State as WsState, WebSocket} from 'websocket13';
import Zlib from 'zlib';

import EMsg from '../enums-steam/EMsg';
import EResult from '../enums-steam/EResult';

import Protos from '../protobuf-generated/load';
import {CMsgClientHello, CMsgClientLogonResponse, CMsgMulti, CMsgProtoBufHeader} from '../protobuf-generated/types';
import ITransport, {ApiRequest, ApiResponse} from './ITransport';
import {eresultError} from '../helpers';

const debug = createDebug('steam-session:WebSocketCMTransport');
const debugVerbose = debug.extend('verbose');

const PROTOCOL_VERSION = 65580;
const PROTO_MASK = 0x80000000;

let g_CmListRetrievalSemaphore = new Semaphore();
let g_CmListCache = new TTLCache<CmServer[]>(1000 * 60 * 5); // cache for 5 minutes

interface CmServer {
	endpoint: string;
	legacy_endpoint?: string;
	type: string;
	dc?: string;
	realm: string;
	load?: string;
	wtd_load?: string;
}

export default class WebSocketCMTransport implements ITransport {
	_connectTimeout = 1000;
	_webClient: HttpClient;
	_agent: Agent;
	_localAddress?: string;
	_websocket: any;
	_jobs: any;
	_clientSessionId = 0;

	constructor(webClient: HttpClient, agent: Agent, localAddress?: string) {
		this._webClient = webClient;
		this._agent = agent;
		this._localAddress = localAddress;
		this._websocket = null;
		this._jobs = {};
	}

	async sendRequest(request: ApiRequest): Promise<ApiResponse> {
		for (let tryCount = 1; tryCount <= 3; tryCount++) {
			try {
				let targetName = `${request.apiInterface}.${request.apiMethod}#${request.apiVersion}`;
				return await this._sendMessage(EMsg.ServiceMethodCallFromClientNonAuthed, request.requestData, targetName);
			} catch (ex) {
				if (ex.eresult && [EResult.TryAnotherCM, EResult.ServiceUnavailable].includes(ex.eresult)) {
					continue;
				}

				throw ex;
			}
		}
	}

	close() {
		if (this._websocket && this._websocket.state == WsState.Connected) {
			this._websocket.disconnect();
		}
	}

	_connectToCM(): Promise<void> {
		return new Promise(async (resolve, reject) => {
			try {
				if (this._websocket && this._websocket.state == WsState.Connecting) {
					// Just wait for the previous connection attempt to succeed

					let connected, error;

					connected = () => {
						this._websocket.removeListener('error', error);
						resolve();
					};

					error = (err) => {
						this._websocket.removeListener('connected', connected);
						reject(err);
					};

					this._websocket.once('connected', connected);
					this._websocket.once('error', error);
					return;
				}

				debug('_connectToCM()');

				let cmList = (await this._getCMList())
					.filter(cm => cm.type == 'websockets' && cm.realm == 'steamglobal');

				// Choose a CM at random
				let randUpperBound = Math.min(20, cmList.length);
				let cm = cmList[Math.floor(Math.random() * randUpperBound)];

				debug(`Connecting to ${cm.endpoint}`);

				let resolved = false;
				this._websocket = new WebSocket(`wss://${cm.endpoint}/cmsocket/`, {
					connection: {
						agent: this._agent,
						localAddress: this._localAddress
					}
				});

				this._websocket.setTimeout(this._connectTimeout);
				this._websocket.on('timeout', () => {
					if (resolved) {
						return;
					}

					debug(`Connecting to ${cm.endpoint} timed out after ${this._connectTimeout} ms`);
					this._connectTimeout = Math.min(10000, this._connectTimeout * 2);

					this._websocket.disconnect();
					this._connectToCM().then(resolve).catch(reject);
				});

				this._websocket.on('connected', async () => {
					this._websocket.setTimeout(0);

					debug(`Connected to ${cm.endpoint}`);

					let hello: CMsgClientHello = {protocol_version: PROTOCOL_VERSION};
					// @ts-ignore
					await this._sendMessage(EMsg.ClientHello, Protos.CMsgClientHello.encode(hello).finish());

					resolved = true;
					resolve();
				});

				this._websocket.on('disconnected', (code, reason, initiatedByUs) => {
					debug(`${initiatedByUs ? 'Disconnected' : 'Unexpectedly disconnected'} from ${cm.endpoint}: ${code} (${reason})`);
					this._websocket = null;
				});

				this._websocket.on('error', (err) => {
					debug(`Error ${resolved ? 'in' : 'connecting'} WebSocket with ${cm.endpoint}`);
					if (!resolved) {
						reject(err);
					}
				});

				this._websocket.on('message', (type, msg) => {
					if (type != WsFrameType.Data.Binary) {
						debug(`Received unexpected frame type from ${cm.endpoint}: ${type.toString(16)}`);
						return;
					}

					this._handleWsMessage(msg);
				});
			} catch (ex) {
				reject(ex);
			}
		});
	}

	async _getCMList(): Promise<CmServer[]> {
		let release = await g_CmListRetrievalSemaphore.waitAsync();
		try {
			let cmList = g_CmListCache.get('cmlist');
			if (cmList) {
				debug('Using cached CM list');
				return cmList;
			}

			cmList = await this._fetchCMList();
			g_CmListCache.add('cmlist', cmList);

			return cmList;
		} finally {
			release();
		}
	}

	async _fetchCMList(): Promise<CmServer[]> {
		debug('Fetching CM list');

		let result = await this._webClient.request({
			method: 'GET',
			url: 'https://api.steampowered.com/ISteamDirectory/GetCMListForConnect/v0001/?cellid=0&format=vdf',
			headers: {
				'user-agent': 'Valve/Steam HTTP Client 1.0',
				'accept-charset': 'ISO-8859-1,utf-8,*;q=0.7',
				accept: 'text/html,*/*;q=0.9'
			}
		});

		if (result.statusCode != 200) {
			let err:any = new Error('Unable to fetch CM list');
			err.code = result.statusCode;
			throw err;
		}

		let parsedResult = VDF.parse(result.textBody);
		if (!parsedResult.response || !parsedResult.response.serverlist) {
			throw new Error('Malformed CM list response');
		}

		if (parsedResult.response.success != 1) {
			throw new Error(parsedResult.response.message || 'GetCMListForConnect failure');
		}

		let serverList = parsedResult.response.serverlist;
		serverList.length = Object.keys(serverList).length;

		/** @var {CmServer[]} serverList */
		serverList = Array.prototype.slice.call(serverList);
		serverList.forEach((server) => {
			server.load = parseFloat(server.load);
			server.wtd_load = parseFloat(server.wtd_load);
		});

		serverList.sort((a, b) => a.wtd_load < b.wtd_load ? -1 : 1);

		debug(`Fetched ${serverList.length} CMs`);

		return Array.prototype.slice.call(serverList);
	}

	_handleWsMessage(msg: Buffer): void {
		let rawEmsg = msg.readUInt32LE(0);
		let hdrLength = msg.readUInt32LE(4);
		let hdrBuf = msg.slice(8, 8 + hdrLength);
		let msgBody = msg.slice(8 + hdrLength);

		if (!(rawEmsg & PROTO_MASK)) {
			throw new Error(`Received unexpected non-protobuf message ${rawEmsg}`);
		}

		// @ts-ignore
		let decodedProtoHeader = Protos.CMsgProtoBufHeader.decode(hdrBuf);
		// @ts-ignore
		let protoHeader = Protos.CMsgProtoBufHeader.toObject(decodedProtoHeader, {longs: String});

		if (protoHeader.client_sessionid && protoHeader.client_sessionid != this._clientSessionId) {
			debugVerbose(`Got new client session id ${protoHeader.client_sessionid}`);
			this._clientSessionId = protoHeader.client_sessionid;
		}

		let eMsg = (rawEmsg & ~PROTO_MASK) as EMsg;
		if (eMsg != EMsg.Multi) {
			debugVerbose(`Receive: ${EMsg[eMsg] || eMsg} (${protoHeader.target_job_name})`);
		}

		if (protoHeader.jobid_target && this._jobs[protoHeader.jobid_target]) {
			let {resolve, timeout} = this._jobs[protoHeader.jobid_target];
			clearTimeout(timeout);
			delete this._jobs[protoHeader.jobid_target];

			let response: ApiResponse = {
				result: protoHeader.eresult,
				errorMessage: protoHeader.error_message,
				responseData: msgBody
			};

			return resolve(response);
		}

		// this isn't a response message, so figure out what it is
		switch (eMsg) {
			case EMsg.ClientLogOnResponse:
				// The only time we expect to receive ClientLogOnResponse is when the CM is telling us to try another CM
				// @ts-ignore
				let decodedLogOnResponse = Protos.CMsgClientLogonResponse.decode(msgBody);
				// @ts-ignore
				let logOnResponse: CMsgClientLogonResponse = Protos.CMsgClientLogonResponse.toObject(decodedLogOnResponse, {longs: String});
				debug(`Received ClientLogOnResponse with result: ${EResult[logOnResponse.eresult] || logOnResponse.eresult}`);

				if (this._websocket.state == WsState.Connected) {
					this._websocket.disconnect();
					this._websocket = null;
				}

				for (let i in this._jobs) {
					let {reject, timeout} = this._jobs[i];
					clearTimeout(timeout);
					reject(eresultError(logOnResponse.eresult));
				}
				break;

			case EMsg.Multi:
				// noinspection JSIgnoredPromiseFromCall
				this._processMultiMsg(msgBody);
				break;

			default:
				debug(`Received unexpected message: ${eMsg}`);
		}
	}

	async _processMultiMsg(body: Buffer): Promise<void> {
		// @ts-ignore
		let decodedBody = Protos.CMsgMulti.decode(body);
		// @ts-ignore
		let multi: CMsgMulti = Protos.CMsgMulti.toObject(decodedBody, {longs: String});

		let payload = multi.message_body;

		if (multi.size_unzipped) {
			// We need to decompress it
			payload = await new Promise((resolve, reject) => {
				Zlib.gunzip(payload, (err, unzipped) => {
					if (err) {
						return reject(err);
					}

					resolve(unzipped);
				});
			});
		}

		while (payload.length > 0) {
			let chunkSize = payload.readUInt32LE(0);
			this._handleWsMessage(payload.slice(4, 4 + chunkSize));
			payload = payload.slice(4 + chunkSize);
		}
	}

	async _sendMessage(eMsg: EMsg, body: Buffer, serviceMethodName?: string): Promise<any> {
		if (!this._websocket || this._websocket.state != WsState.Connected) {
			await this._connectToCM();
		}

		return await new Promise((resolve, reject) => {
			let protoHeader: CMsgProtoBufHeader = {
				steamid: '0',
				client_sessionid: eMsg != EMsg.ServiceMethodCallFromClientNonAuthed ? this._clientSessionId : 0,
			};

			if (eMsg == EMsg.ServiceMethodCallFromClientNonAuthed) {
				let jobIdBuffer = randomBytes(8);
				jobIdBuffer[0] &= 0x7f; // make sure it's always a positive value
				let jobId = jobIdBuffer.readBigInt64BE(0).toString(10);

				protoHeader.jobid_source = jobId;
				protoHeader.target_job_name = serviceMethodName;
				protoHeader.realm = 1;

				let timeout = setTimeout(() => {
					reject(new Error(`Request ${serviceMethodName} timed out`));
				}, 5000);

				this._jobs[jobId] = {resolve, reject, timeout};
			} else {
				// There's no response, so just resolve right now
				resolve(undefined);
			}

			// @ts-ignore
			let encodedProtoHeader: Buffer = Protos.CMsgProtoBufHeader.encode(protoHeader).finish();
			let header = Buffer.alloc(8);
			header.writeUInt32LE(((eMsg as number) | PROTO_MASK) >>> 0, 0);
			header.writeUInt32LE(encodedProtoHeader.length, 4);

			debugVerbose(`Send: ${EMsg[eMsg] || eMsg} (${serviceMethodName})`);

			this._websocket.send(Buffer.concat([
				header,
				encodedProtoHeader,
				body
			]));
		});
	}
}

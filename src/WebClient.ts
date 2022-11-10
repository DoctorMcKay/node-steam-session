import createDebug from 'debug';
import HTTPS from 'https';
import QueryString, {ParsedUrlQueryInput} from 'querystring';
import {IncomingMessage, OutgoingHttpHeaders} from 'http';
import {Readable as ReadableStream} from 'stream';
import {randomBytes} from 'crypto';

const debug = createDebug('steam-session:webclient');

export interface WebClientOptions {
	agent?: HTTPS.Agent;
}

export interface RequestOptions {
	headers?: OutgoingHttpHeaders;
	queryString?: ParsedUrlQueryInput;
}

export interface ResponseData {
	res: IncomingMessage;
	body: any;
}

export default class WebClient {
	_agent: HTTPS.Agent;

	constructor(options: WebClientOptions) {
		this._agent = options.agent || new HTTPS.Agent({keepAlive: true});
	}

	async get(url: string, options?: RequestOptions): Promise<ResponseData> {
		return await this._req(buildUrl(url, options), null, buildRequestOptions('GET', options));
	}

	async post(url: string, body?: string|Buffer, options?: RequestOptions): Promise<ResponseData> {
		return await this._req(buildUrl(url, options), body, buildRequestOptions('POST', options));
	}

	async postEncoded(url: string, body: object, encoding: string = 'json', options?: RequestOptions): Promise<ResponseData> {
		let encodedBody:string|Buffer,
			contentType:string;
		switch (encoding) {
			case 'json':
				contentType = 'application/json';
				encodedBody = JSON.stringify(body);
				break;

			case 'url':
				contentType = 'application/x-www-form-urlencoded';
				encodedBody = QueryString.stringify(body as any);
				break;

			case 'multipart':
				let boundary = '-----------------------------' + randomBytes(20).toString('hex');
				contentType = `multipart/form-data; boundary=${boundary}`;
				let encodedBodyParts = [];
				for (let i in body) {
					let head = `--${boundary}\r\nContent-Disposition: form-data; name="${i}"\r\n\r\n`;
					let tail = '\r\n';

					encodedBodyParts = encodedBodyParts.concat([
						Buffer.from(head, 'utf8'),
						Buffer.isBuffer(body[i]) ? body[i] : Buffer.from(body[i].toString(), 'utf8'),
						Buffer.from(tail, 'utf8')
					]);
				}

				encodedBodyParts.push(Buffer.from(`--${boundary}--\r\n`, 'utf8'));
				encodedBody = Buffer.concat(encodedBodyParts);
				break;

			default:
				throw new Error(`Unsupported encoding "${encoding}"`);
		}

		return await this._req(buildUrl(url, options), encodedBody, buildRequestOptions('POST', options, {'content-type': contentType}));
	}

	_req(url: string, body: ReadableStream|string|Buffer|null, options: HTTPS.RequestOptions): Promise<ResponseData> {
		return new Promise((resolve, reject) => {
			let parsedUrl = urlToHttpOptions(new URL(url));

			if (Buffer.isBuffer(body) || typeof body == 'string') {
				options.headers = options.headers || {};
				options.headers['content-length'] = Buffer.byteLength(body);
			} else if (!body) {
				options.headers = options.headers || {};
				options.headers['content-length'] = 0;
			}

			let req = HTTPS.request({...parsedUrl, ...options, agent: this._agent}, (res) => {
				let chunks:Buffer[] = [];
				res.on('data', chunk => chunks.push(chunk));
				res.on('end', () => {
					let body:Buffer|string|object = Buffer.concat(chunks);

					let contentType = (res.headers['content-type'] || '').split(';')[0].toLowerCase().trim();
					if (contentType.startsWith('text/') || contentType == 'application/json') {
						body = body.toString('utf8');
					}

					if (contentType == 'application/json') {
						try {
							body = JSON.parse(body as string);
						} catch (ex) {
							debug('error parsing json response %o', ex);
						}
					}

					resolve({res, body});
				});
			});

			req.on('error', reject);

			if (body instanceof ReadableStream) {
				body.pipe(req);
			} else if (Buffer.isBuffer(body) || typeof body == 'string') {
				req.end(body);
			} else {
				req.end();
			}
		});
	}
}

function buildUrl(url: string, options: RequestOptions): string {
	options = options || {};

	if (options.queryString && Object.keys(options.queryString).length > 0) {
		url += url.includes('?') ? '&' : '?';
		url += QueryString.stringify(options.queryString);
	}

	return url;
}

function buildRequestOptions(method: string, options: RequestOptions, extraHeaders?: object): HTTPS.RequestOptions {
	options = options || {};

	let output:HTTPS.RequestOptions = {method};
	if (options.headers) {
		output.headers = options.headers;
	}

	if (extraHeaders) {
		output.headers = output.headers || {};
		output.headers = {...output.headers, ...extraHeaders};
	}

	output.rejectUnauthorized = false;

	return output;
}

// Polyfill for node versions prior to 14.18.0
function urlToHttpOptions(url: any): any {
	let options:any = {
		protocol: url.protocol,
		hostname: typeof url.hostname == 'string' &&
		url.hostname.startsWith('[')
			? url.hostname.slice(1, -1)
			: url.hostname,
		hash: url.hash,
		search: url.search,
		pathname: url.pathname,
		path: `${url.pathname || ''}${url.search || ''}`,
		href: url.href,
	};
	if (url.port !== '') {
		options.port = Number(url.port);
	}
	if (url.username || url.password) {
		options.auth = [url.username, url.password].map(v => decodeURIComponent(v || '')).join(':');
	}
	return options;
}

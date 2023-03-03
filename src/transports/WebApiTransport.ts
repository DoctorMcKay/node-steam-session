import createDebug from 'debug';
import ITransport, {ApiRequest, ApiResponse} from './ITransport';
import WebClient, {ResponseData} from '../WebClient';
import EResult from '../enums-steam/EResult';
import {API_HEADERS} from '../helpers';

const debug = createDebug('steam-session:webapitransport');

// Assume everything is a POST request unless it's specifically listed as a GET request
const GET_REQUESTS = [
	'IAuthenticationService/GetPasswordRSAPublicKey/v1'
];

const WEBAPI_BASE = 'https://api.steampowered.com';

export interface WebApiTransportOptions {
	httpProxy?: string,
	socksProxy?: string
}

export default class WebApiTransport implements ITransport {
	_client: WebClient;

	constructor(client: WebClient) {
		this._client = client;
	}

	async sendRequest(request: ApiRequest): Promise<ApiResponse> {
		let urlPath = `I${request.apiInterface}Service/${request.apiMethod}/v${request.apiVersion}`;
		let url = `${WEBAPI_BASE}/${urlPath}/`;
		let method = GET_REQUESTS.includes(urlPath) ? 'GET' : 'POST';
		let headers = {...API_HEADERS, ...(request.headers || {})};

		let queryString:any = {};
		let form:any = {};

		if (request.accessToken) {
			queryString.access_token = request.accessToken;
		}

		if (request.requestData && request.requestData.length > 0) {
			(method == 'GET' ? queryString : form).input_protobuf_encoded = request.requestData.toString('base64');
		}

		debug('%s %s %o %o', method, url, queryString, form);

		let result:ResponseData;
		if (method == 'GET') {
			result = await this._client.get(url, {queryString, headers});
		} else if (Object.keys(form).length == 0) {
			result = await this._client.post(url, null, {queryString, headers});
		} else {
			result = await this._client.postEncoded(url, form, 'multipart', {queryString, headers});
		}

		if (result.res.statusCode < 200 || result.res.statusCode >= 300) {
			let err:any = new Error(`WebAPI error ${result.res.statusCode}`);
			err.code = result.res.statusCode;
			throw err;
		}

		let apiResponse:ApiResponse = {};

		let eresultHeader = result.res.headers['x-eresult'];
		let errorMessageHeader = result.res.headers['x-error_message'];

		if (typeof eresultHeader == 'string') {
			apiResponse.result = parseInt(eresultHeader) as EResult;
		}

		if (typeof errorMessageHeader == 'string') {
			apiResponse.errorMessage = errorMessageHeader;
		}

		if (result.body && result.body.length > 0) {
			apiResponse.responseData = result.body;
		}

		return apiResponse;
	}

	// eslint-disable-next-line @typescript-eslint/no-empty-function
	close() {}
}

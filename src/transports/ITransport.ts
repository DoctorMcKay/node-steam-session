import EResult from '../enums-steam/EResult';

export interface ApiRequest {
    apiInterface: string;
    apiMethod: string;
    apiVersion: number;
    accessToken?: string;
    requestData?: any;
    headers?: any;
}

export interface ApiResponse {
    result?: EResult;
    errorMessage?: string;
    responseData?: any;
}

export default interface ITransport {
    /**
     * Sends a request to Steam.
     *
     * @param {ApiRequest} request
     * @return {Promise<ApiResponse>}
     */
    sendRequest(request: ApiRequest): Promise<ApiResponse>;

    /**
     * Cleans up any resources allocated by the transport.
     */
    close(): void;
}

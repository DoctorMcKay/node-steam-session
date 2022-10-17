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
    sendRequest(request: ApiRequest): Promise<ApiResponse>;
}

import Protos from './protobuf-generated/load';

const PROTO_MAP = {
	Authentication_GenerateAccessTokenForApp: 'CAuthentication_AccessToken_GenerateForApp'
};

export function getProtoForMethod(apiInterface, apiMethod): {request: any, response: any} {
	let signature = [apiInterface, apiMethod].join('_');
	let protoDefinitionName = PROTO_MAP[signature] || `C${signature}`;

	let request = Protos[`${protoDefinitionName}_Request`];
	let response = Protos[`${protoDefinitionName}_Response`];

	if (signature == 'CAuthentication_BeginAuthSessionViaCredentials') {
		request += '_BinaryGuardData';
	}

	return {request, response};
}

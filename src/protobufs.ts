import Protos from './protobuf-generated/load';

const PROTO_MAP = {
	Authentication_GenerateAccessTokenForApp: 'CAuthentication_AccessToken_GenerateForApp'
};

export function getProtoForMethod(apiInterface, apiMethod): {request: any, response: any} {
	let signature = [apiInterface, apiMethod].join('_');
	let protoDefinitionName = PROTO_MAP[signature] || `C${signature}`;

	let requestDefinitionName = `${protoDefinitionName}_Request`;
	let responseDefinitionName = `${protoDefinitionName}_Response`;

	if (signature == 'Authentication_BeginAuthSessionViaCredentials') {
		requestDefinitionName += '_BinaryGuardData';
	}

	let request = Protos[requestDefinitionName];
	let response = Protos[responseDefinitionName];

	return {request, response};
}

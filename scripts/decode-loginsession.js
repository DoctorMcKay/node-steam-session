const FS = require('fs');

const Protos = require('../dist/protobuf-generated/load.js').default;

if (!process.argv[2] || !FS.existsSync(process.argv[2])) {
	console.error('Usage: node decode-loginsession.js <path to har file> [optional path to output json file]');
	process.exit(1);
}

let har;
let output = [];
try {
	har = JSON.parse(FS.readFileSync(process.argv[2], {encoding: 'utf8'}));
	if (!har.log || !har.log.entries || !Array.isArray(har.log.entries)) {
		throw new Error();
	}
} catch (ex) {
	console.error('Error: Provided file does not appear to be a valid HAR');
	process.exit(2);
}

har.log.entries.forEach(({request, response}) => {
	let match = request.url.match(/^https:\/\/api\.steampowered\.com\/IAuthenticationService\/([^\/]+)\/v\d+[?\/]?/);
	if (!match) {
		// Not a relevant request for us
		return;
	}

	let apiMethod = match[1];
	let requestProto = Protos[`CAuthentication_${apiMethod}_Request`];
	let responseProto = Protos[`CAuthentication_${apiMethod}_Response`];
	if (!requestProto || !responseProto) {
		return;
	}

	let params = (request.method == 'GET' ? request.queryString : request.postData.params) || [];
	let inputParam = params.find(v => v.name == 'input_protobuf_encoded');
	let inputEncoded = Buffer.from(inputParam?.value || '', 'base64');

	if (response.content.encoding != 'base64') {
		return;
	}

	let responseEncoded = Buffer.from(response.content.text, 'base64');

	let decodedRequest = decode(requestProto, inputEncoded);
	let decodedResponse = decode(responseProto, responseEncoded);

	console.log(`===== ${apiMethod} =====`);
	console.log('Request:');
	console.log(decodedRequest);
	console.log('Response:');
	console.log(decodedResponse);

	output.push({
		method: apiMethod,
		request: decodedRequest,
		response: decodedResponse
	});
});

if (process.argv[3]) {
	fixupObject(output);
	FS.writeFileSync(process.argv[3], JSON.stringify(output, undefined, '\t'));
	console.log(`\nOutput file written to ${process.argv[3]}`);
}

function fixupObject(obj) {
	for (let i in obj) {
		if (Buffer.isBuffer(obj[i])) {
			obj[i] = obj[i].toString('base64');
		} else if (obj[i] && typeof obj[i] == 'object') {
			fixupObject(obj[i]);
		}
	}
}

function decode(proto, encoded) {
	let decodedBody = proto.decode(encoded);
	return proto.toObject(decodedBody, {longs: String});
}

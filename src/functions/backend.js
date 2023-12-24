// src/index.js
var encoder = new TextEncoder();
if (typeof __non_webpack_require__ !== "undefined") {
	const crypto2 = __non_webpack_require__("crypto");
}

var src_default = {
	async fetch(request, env) {
		let { host, pathname } = new URL(request.url);
		const { gateway_hosts } = env;
		const gateway_host_list = gateway_hosts.split(",");

		if (gateway_host_list.includes(host)) {
			return await handleBackEndTraffic(request, env);
		}

		if (host.startsWith("proxy")) {
			return await fetch(request);
		}

		const response_message = {
			message: `Request not authorized : Bad Gateway Server : ${host}`,
		};
		return new Response(JSON.stringify(response_message), { status: 401 });
	},
};

async function sha256(message) {
	/**
	 * calculates sha256
	 */
	const data = encoder.encode(message);
	const hashBuffer = await crypto.subtle.digest("SHA-256", data);
	return Array.prototype.map
		.call(new Uint8Array(hashBuffer), (x) => ("00" + x.toString(16)).slice(-2))
		.join("");
}

async function is_signature_valid(signature, request, secret) {
	/**
	 * validates request signature
	 */
	const { host, pathname } = new URL(request.url);
	const url = `${host}${pathname}`;
	const method = request.method.toUpperCase();
	const headers = request.headers;
	const expectedSignature = await sha256(`${method}${url}${headers}${secret}`);
	return signature === expectedSignature;
}

async function createCacheKey(apiKey, secretToken, pathname) {
	/**
	 * create cache key for requests based on api key and pathname
	 */
	return await sha256(`${pathname}-${apiKey}-${secretToken}`);
}

async function handleBackEndTraffic(request, env) {
	/**
	 * handles traffic
	 */

	const { host, pathname } = new URL(request.url);
	const { gateway_hosts } = env;
	const gateway_host_list = gateway_hosts.split(",");

	if (pathname.startsWith("/api/v1")) {
		const apiKey = request.headers.get("X-API-KEY");

		const secretToken = request.headers.get("X-SECRET-TOKEN");

		if (!apiKey || !secretToken) {
			const response_message = { message: "Request not authorized" };
			return new Response(JSON.stringify(response_message), { status: 401 });
		}

		const is_api_valid = await compareApiKeys(apiKey, env);

		if (!is_api_valid) {
			const response_message = { message: "Request not authorized : Invalid API Key" };
			return new Response(JSON.stringify(response_message), { status: 401 });
		}

		const is_secret_token_valid = await compareSecretToken(secretToken, env);

		if (!is_secret_token_valid) {
			const response_message = { message: "Request not authorized : Invalid Secret Token" };
			return new Response(JSON.stringify(response_message), { status: 401 });
		}

		const signature = request.headers.get("X-Signature");

		let is_valid_signature = await is_signature_valid(signature, request, secretToken);

		const { gateway_host } = env;

		if (!is_valid_signature && host.toLowerCase() === gateway_host) {
			const response_message = { message: "Request not authorized : Invalid Signature" };
			return new Response(JSON.stringify(response_message), { status: 401 });
		}

		// Caching get requests only
		const cacheKey = await createCacheKey(apiKey, secretToken, pathname);

		if (request.method.toUpperCase() == "GET") {
			return await fetch(request, {
				cf: {
					cacheTtl: 10800,
					cacheEverything: true,
					cacheKey,
				},
			});
		}

		// only cache get requests
		return await fetch(request);
	}
	// This means all other paths are returned
	// Redirects all www and client requests to root

	let new_host;
	if (host.startsWith("www")) {
		new_host == "eod-stock-api.site";
	}
	if (host.startsWith("client")) {
		new_host == "eod-stock-api.site";
	}
	let _url = `${new_host}${path}`;

	const new_request = new Request(_url, {
		method: request.method,
		headers: new Headers(request.headers),
		body: request.body,
		cors: request.cors,
		credentials: request.credentials,
	});

	return await fetch(new_request);
}

async function compareApiKeys(apiKey, env) {
	/**
	 * compares two api keys to check if they are equal
	 */
	const { api_key } = env;
	return apiKey === api_key;
}

async function compareSecretToken(token, env) {
	/**
	 * compares secret token with the one in environment to see if equal
	 */
	const { secretTokenFlare } = env;
	return token === secretTokenFlare;
}

export { src_default as default };

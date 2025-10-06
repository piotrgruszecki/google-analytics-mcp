import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

// Define our MCP agent with GA4 tools
export class MyMCP extends McpAgent {
	server = new McpServer({
		name: "Google Analytics MCP Server",
		version: "1.0.0",
	});

	// Helper to get access token from service account
	async getAccessToken(credentials: any): Promise<string> {
		const now = Math.floor(Date.now() / 1000);
		const exp = now + 3600;

		const header = {
			alg: "RS256",
			typ: "JWT",
		};

		const claimSet = {
			iss: credentials.client_email,
			scope: "https://www.googleapis.com/auth/analytics.readonly",
			aud: "https://oauth2.googleapis.com/token",
			exp: exp,
			iat: now,
		};

		// Base64URL encode helper
		const base64UrlEncode = (str: string): string => {
			return btoa(str)
				.replace(/\+/g, "-")
				.replace(/\//g, "_")
				.replace(/=/g, "");
		};

		const encodedHeader = base64UrlEncode(JSON.stringify(header));
		const encodedClaimSet = base64UrlEncode(JSON.stringify(claimSet));
		const signatureInput = `${encodedHeader}.${encodedClaimSet}`;

		// Import private key
		const pemHeader = "-----BEGIN PRIVATE KEY-----";
		const pemFooter = "-----END PRIVATE KEY-----";
		const pemContents = credentials.private_key
			.replace(pemHeader, "")
			.replace(pemFooter, "")
			.replace(/\s/g, "");

		// Decode base64 to binary
		const binaryDerString = atob(pemContents);
		const binaryDer = new Uint8Array(binaryDerString.length);
		for (let i = 0; i < binaryDerString.length; i++) {
			binaryDer[i] = binaryDerString.charCodeAt(i);
		}

		const cryptoKey = await crypto.subtle.importKey(
			"pkcs8",
			binaryDer.buffer,
			{
				name: "RSASSA-PKCS1-v1_5",
				hash: "SHA-256",
			},
			false,
			["sign"]
		);

		// Sign the JWT
		const encoder = new TextEncoder();
		const signatureData = encoder.encode(signatureInput);
		const signature = await crypto.subtle.sign(
			"RSASSA-PKCS1-v1_5",
			cryptoKey,
			signatureData
		);

		// Convert signature to base64url
		const signatureArray = new Uint8Array(signature);
		let signatureString = "";
		for (let i = 0; i < signatureArray.length; i++) {
			signatureString += String.fromCharCode(signatureArray[i]);
		}
		const encodedSignature = base64UrlEncode(signatureString);

		const jwt = `${signatureInput}.${encodedSignature}`;

		// Exchange JWT for access token
		const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
		});

		const tokenData = await tokenResponse.json();

		if (!tokenResponse.ok) {
			throw new Error(`Token error: ${JSON.stringify(tokenData)}`);
		}

		return tokenData.access_token;
	}

	async init() {
		// Run a GA4 report
		this.server.tool(
			"run_ga4_report",
			{
				property_id: z.string(),
				start_date: z.string(),
				end_date: z.string(),
				metrics: z.array(z.string()),
				dimensions: z.array(z.string()).optional(),
			},
			async ({ property_id, start_date, end_date, metrics, dimensions }) => {
				try {
					const credentials = JSON.parse(this.env.GOOGLE_APPLICATION_CREDENTIALS);
					const accessToken = await this.getAccessToken(credentials);

					const requestBody = {
						dateRanges: [{ startDate: start_date, endDate: end_date }],
						metrics: metrics.map(name => ({ name })),
						dimensions: dimensions?.map(name => ({ name })) || [],
					};

					const response = await fetch(
						`https://analyticsdata.googleapis.com/v1beta/properties/${property_id}:runReport`,
						{
							method: "POST",
							headers: {
								Authorization: `Bearer ${accessToken}`,
								"Content-Type": "application/json",
							},
							body: JSON.stringify(requestBody),
						}
					);

					const data = await response.json();

					if (!response.ok) {
						return {
							content: [{
								type: "text",
								text: `Error: ${JSON.stringify(data, null, 2)}`
							}],
						};
					}

					return {
						content: [{
							type: "text",
							text: JSON.stringify(data, null, 2)
						}],
					};
				} catch (error) {
					return {
						content: [{
							type: "text",
							text: `Error: ${error.message}`
						}],
					};
				}
			}
		);
	}
}

export default {
	fetch(request: Request, env: Env, ctx: ExecutionContext) {
		const url = new URL(request.url);
		if (url.pathname === "/sse" || url.pathname === "/sse/message") {
			return MyMCP.serveSSE("/sse").fetch(request, env, ctx);
		}
		if (url.pathname === "/mcp") {
			return MyMCP.serve("/mcp").fetch(request, env, ctx);
		}
		return new Response("Not found", { status: 404 });
	},
};
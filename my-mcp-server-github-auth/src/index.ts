import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { BetaAnalyticsDataClient } from "@google-analytics/data";

// Define our MCP agent with GA4 tools
export class MyMCP extends McpAgent {
	server = new McpServer({
		name: "Google Analytics MCP Server",
		version: "1.0.0",
	});

	async init() {
		// Get GA4 properties
		this.server.tool(
			"get_ga4_properties",
			{},
			async () => {
				const credentials = JSON.parse(this.env.GOOGLE_APPLICATION_CREDENTIALS);
				
				// Note: Property listing requires Admin API, not Data API
				// For now, we'll return instructions
				return {
					content: [{
						type: "text",
						text: "To use GA4, you need to provide your property ID. Find it in GA4 > Admin > Property Settings"
					}],
				};
			}
		);

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
					
					const analyticsDataClient = new BetaAnalyticsDataClient({
						credentials: credentials,
					});

					const [response] = await analyticsDataClient.runReport({
						property: `properties/${property_id}`,
						dateRanges: [{ startDate: start_date, endDate: end_date }],
						metrics: metrics.map(name => ({ name })),
						dimensions: dimensions?.map(name => ({ name })) || [],
					});

					return {
						content: [{
							type: "text",
							text: JSON.stringify(response, null, 2)
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
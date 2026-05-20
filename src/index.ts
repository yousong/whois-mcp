#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { whoisAsn, whoisDomain, whoisTld, whoisIp } from 'whoiser';
import { green, red, yellow } from './utils.js'

const config = {
  timeout: parseInt(process.env.WHOIS_TIMEOUT || '1500', 10),
  maxRetries: parseInt(process.env.WHOIS_MAX_RETRIES || '3', 10),
  retryDelay: parseInt(process.env.WHOIS_RETRY_DELAY || '1000', 10),
  follow: 2,
} as const;

async function retryWithBackoff<T>(
  fn: () => Promise<T>,
  maxRetries: number,
  delay: number,
  isTimeout: (result: T) => boolean
): Promise<T> {
  let lastError: Error | undefined;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const result = await fn();
      if (isTimeout(result) && attempt < maxRetries) {
        console.error(yellow(`⚠️ Timeout on attempt ${attempt + 1}, retrying in ${delay}ms...`));
        await new Promise(resolve => setTimeout(resolve, delay));
        continue;
      }
      return result;
    } catch (err) {
      lastError = err as Error;
      if (lastError.message.toLowerCase().includes('timeout') && attempt < maxRetries) {
        console.error(yellow(`⚠️ Timeout on attempt ${attempt + 1}, retrying in ${delay}ms...`));
        await new Promise(resolve => setTimeout(resolve, delay));
      } else {
        throw lastError;
      }
    }
  }
  throw lastError ?? new Error('All retries timed out');
}

function hasTimeoutError(result: unknown): boolean {
  if (typeof result !== 'object' || result === null) return false;
  for (const value of Object.values(result)) {
    if (typeof value === 'object' && value !== null && 'error' in value) {
      return (value as Record<string, unknown>).error === 'Timeout';
    }
  }
  return false;
}

function registerTools(server: McpServer) {
  //TOOL: Domain whois lookup
  server.tool(
    'whois_domain',
    'Looksup whois information about the domain',
    { domain: z.string().min(1) },
    async ({ domain }) => {
      try {
        const result = await retryWithBackoff(
          () => whoisDomain(domain, { timeout: config.timeout, follow: config.follow }),
          config.maxRetries,
          config.retryDelay,
          hasTimeoutError
        );
        return {
          content: [{ type: 'text', text: `Domain whois lookup for: \n${JSON.stringify(result)}` }],
        };
      } catch (err: unknown) {
        const error = err as Error;
        return {
          content: [{ type: 'text', text: `Error: ${error.message}` }],
          isError: true
        };
      }
    }
  );

  //TOOL: TLD whois lookup
  server.tool(
    'whois_tld',
    'Looksup whois information about the Top Level Domain (TLD)',
    { tld: z.string().min(1) },
    async ({ tld }) => {
      try {
        const result = await retryWithBackoff(
          () => whoisTld(tld, config.timeout),
          config.maxRetries,
          config.retryDelay,
          hasTimeoutError
        );
        return {
          content: [{ type: 'text', text: `TLD whois lookup for: \n${JSON.stringify(result)}` }],
        };
      } catch (err: unknown) {
        const error = err as Error;
        return {
          content: [{ type: 'text', text: `Error: ${error.message}` }],
          isError: true
        };
      }
    }
  );

  //TOOL: IP whois lookup
  server.tool(
    'whois_ip',
    'Looksup whois information about the IP',
    { ip: z.string().ip() },
    async ({ ip }) => {
      try {
        const result = await retryWithBackoff(
          () => whoisIp(ip, { timeout: config.timeout }),
          config.maxRetries,
          config.retryDelay,
          hasTimeoutError
        );
        return {
          content: [{ type: 'text', text: `IP whois lookup for: \n${JSON.stringify(result)}` }],
        };
      } catch (err: unknown) {
        const error = err as Error;
        return {
          content: [{ type: 'text', text: `Error: ${error.message}` }],
          isError: true
        };
      }
    }
  );

  //TOOL: ASN whois lookup
  server.tool(
    'whois_as',
    'Looksup whois information about the Autonomous System Number (ASN)',
    { asn: z.string().regex(/^AS\d+$/i).transform(s => parseInt(s.slice(2))) },
    async ({ asn }) => {
      try {
        const result = await retryWithBackoff(
          () => whoisAsn(asn, { timeout: config.timeout }),
          config.maxRetries,
          config.retryDelay,
          hasTimeoutError
        );
        return {
          content: [{ type: 'text', text: `ASN whois lookup for: \n${JSON.stringify(result)}` }],
        };
      } catch (err: unknown) {
        const error = err as Error;
        return {
          content: [{ type: 'text', text: `Error: ${error.message}` }],
          isError: true
        };
      }
    }
  );
}

async function main() {
  const server = new McpServer({
    name: 'whois',
    version: '1.0.0',
    description: 'MCP for whois lookup about domain, IP, TLD, ASN, etc.',
  });
  registerTools(server);

	let transport = new StdioServerTransport();
	await server.connect(transport);

	const cleanup = async () => {
		console.log(yellow('\n⚠️ Shutting down MCP server...'));
    await transport.close();
    process.exit(0);
	};

	process.on('SIGINT', cleanup);
	process.on('SIGTERM', cleanup);

	console.error(green('✅ Whois MCP Server running on stdio'));
}

function handleError(error: any) {
	console.error(red('\n🚨  Error initializing Whois MCP server:\n'));
	console.error(yellow(`   ${error.message}\n`));
}

main().catch((error) => {
	handleError(error);
});

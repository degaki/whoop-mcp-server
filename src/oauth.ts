// OAuth 2.1 provider for the Claude <-> MCP-server connection.
//
// This makes YOUR server an OAuth Authorization Server + Protected Resource,
// which is what Claude's custom-connector flow requires. It is unrelated to the
// WHOOP OAuth (that one stays server<->WHOOP and keeps your WHOOP token on this box).
//
// Single-user design: the only "user" is the owner, gated by a password
// (AUTH_PASSWORD, falling back to MCP_SECRET). Claude authenticates via standard
// Authorization Code + PKCE, with Dynamic Client Registration.

import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';
import type { Express, Request, Response, RequestHandler } from 'express';
import express from 'express';

// ---------- storage interface ----------

export interface ClientRec {
	client_id: string;
	client_secret: string | null;
	redirect_uris: string[];
	created_at: number;
}

export interface CodeRec {
	code: string;
	client_id: string;
	redirect_uri: string;
	code_challenge: string;
	scope: string;
	expires_at: number;
}

export interface TokenRec {
	token_hash: string;
	type: 'access' | 'refresh';
	client_id: string;
	scope: string;
	expires_at: number;
}

export interface OAuthStore {
	saveClient(c: ClientRec): void;
	getClient(id: string): ClientRec | null;
	saveCode(c: CodeRec): void;
	takeCode(code: string): CodeRec | null; // fetch AND delete (single use)
	saveToken(t: TokenRec): void;
	getToken(hash: string): TokenRec | null;
	deleteToken(hash: string): void;
}

// ---------- helpers ----------

function b64url(buf: Buffer): string {
	return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function randomToken(): string {
	return b64url(randomBytes(32));
}

function sha256hex(input: string): string {
	return createHash('sha256').update(input).digest('hex');
}

function pkceChallengeFromVerifier(verifier: string): string {
	return b64url(createHash('sha256').update(verifier).digest());
}

function safeEqual(a: string, b: string): boolean {
	const ba = Buffer.from(a);
	const bb = Buffer.from(b);
	if (ba.length !== bb.length) return false;
	return timingSafeEqual(ba, bb);
}

function escapeHtml(s: string): string {
	return s
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#39;');
}

function baseUrl(req: Request, publicUrl: string): string {
	if (publicUrl) return publicUrl.replace(/\/+$/, '');
	const proto = String(req.headers['x-forwarded-proto'] ?? 'https').split(',')[0].trim();
	const host = req.headers['host'];
	return `${proto}://${host}`;
}

// ---------- mount ----------

export interface MountOptions {
	store: OAuthStore;
	ownerPassword: string;
	publicUrl?: string; // e.g. https://whoop.degaki.me  (optional; derived from request if absent)
	resourcePath?: string; // default '/mcp'
	accessTtlSec?: number; // default 3600
	refreshTtlSec?: number; // default 60*60*24*30
	codeTtlSec?: number; // default 600
}

export interface MountResult {
	requireBearer: RequestHandler;
}

export function mountOAuth(app: Express, opts: MountOptions): MountResult {
	const store = opts.store;
	const ownerPassword = opts.ownerPassword;
	const publicUrl = opts.publicUrl ?? '';
	const resourcePath = opts.resourcePath ?? '/mcp';
	const ACCESS_TTL = opts.accessTtlSec ?? 3600;
	const REFRESH_TTL = opts.refreshTtlSec ?? 60 * 60 * 24 * 30;
	const CODE_TTL = opts.codeTtlSec ?? 600;

	const urlencoded = express.urlencoded({ extended: false });
	const json = express.json();

	// --- discovery: protected resource metadata (RFC 9728) ---
	const protectedResourceMeta = (req: Request, res: Response): void => {
		const base = baseUrl(req, publicUrl);
		res.json({
			resource: `${base}${resourcePath}`,
			authorization_servers: [base],
			bearer_methods_supported: ['header'],
			scopes_supported: ['mcp'],
		});
	};
	app.get('/.well-known/oauth-protected-resource', protectedResourceMeta);
	// Some clients append the resource path to the well-known lookup:
	app.get('/.well-known/oauth-protected-resource/*', protectedResourceMeta);

	// --- discovery: authorization server metadata (RFC 8414) ---
	const asMeta = (req: Request, res: Response): void => {
		const base = baseUrl(req, publicUrl);
		res.json({
			issuer: base,
			authorization_endpoint: `${base}/oauth/authorize`,
			token_endpoint: `${base}/oauth/token`,
			registration_endpoint: `${base}/oauth/register`,
			response_types_supported: ['code'],
			grant_types_supported: ['authorization_code', 'refresh_token'],
			code_challenge_methods_supported: ['S256'],
			token_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
			scopes_supported: ['mcp'],
		});
	};
	app.get('/.well-known/oauth-authorization-server', asMeta);
	app.get('/.well-known/oauth-authorization-server/*', asMeta);

	// --- dynamic client registration (RFC 7591) ---
	app.post('/oauth/register', json, (req: Request, res: Response) => {
		const body = (req.body ?? {}) as Record<string, unknown>;
		const redirectUris = Array.isArray(body.redirect_uris) ? (body.redirect_uris as string[]) : [];
		if (redirectUris.length === 0) {
			res.status(400).json({ error: 'invalid_redirect_uri', error_description: 'redirect_uris required' });
			return;
		}
		const clientId = `mcp_${randomToken()}`;
		const client: ClientRec = {
			client_id: clientId,
			client_secret: null, // public client; PKCE provides the security
			redirect_uris: redirectUris,
			created_at: Date.now(),
		};
		store.saveClient(client);
		res.status(201).json({
			client_id: clientId,
			redirect_uris: redirectUris,
			token_endpoint_auth_method: 'none',
			grant_types: ['authorization_code', 'refresh_token'],
			response_types: ['code'],
		});
	});

	// --- authorization endpoint: GET shows the owner password form ---
	app.get('/oauth/authorize', (req: Request, res: Response) => {
		const q = req.query as Record<string, string>;
		const client = q.client_id ? store.getClient(q.client_id) : null;
		if (!client) {
			res.status(400).send('Unknown client_id');
			return;
		}
		if (!q.redirect_uri || !client.redirect_uris.includes(q.redirect_uri)) {
			res.status(400).send('redirect_uri not registered for this client');
			return;
		}
		if (q.code_challenge_method && q.code_challenge_method !== 'S256') {
			res.status(400).send('Only S256 PKCE is supported');
			return;
		}
		if (!q.code_challenge) {
			res.status(400).send('code_challenge (PKCE) required');
			return;
		}
		const hidden = (name: string) =>
			`<input type="hidden" name="${name}" value="${escapeHtml(q[name] ?? '')}">`;
		res.set('Content-Type', 'text/html').send(`<!doctype html>
<html lang="pt-br"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Autorizar acesso</title>
<style>body{font-family:system-ui,sans-serif;max-width:380px;margin:12vh auto;padding:0 20px}
h1{font-size:1.2rem}input[type=password]{width:100%;padding:10px;font-size:1rem;box-sizing:border-box}
button{margin-top:12px;width:100%;padding:10px;font-size:1rem;cursor:pointer}
.hint{color:#666;font-size:.85rem}</style></head>
<body>
<h1>Autorizar o Claude a acessar seu WHOOP MCP</h1>
<p class="hint">Digite a senha do servidor para liberar o acesso.</p>
<form method="POST" action="/oauth/authorize">
${hidden('client_id')}${hidden('redirect_uri')}${hidden('state')}
${hidden('code_challenge')}${hidden('code_challenge_method')}${hidden('scope')}
${hidden('response_type')}${hidden('resource')}
<input type="password" name="owner_password" placeholder="Senha do servidor" autofocus required>
<button type="submit">Autorizar</button>
</form>
</body></html>`);
	});

	// --- authorization endpoint: POST validates password, issues code ---
	app.post('/oauth/authorize', urlencoded, (req: Request, res: Response) => {
		const b = (req.body ?? {}) as Record<string, string>;
		const client = b.client_id ? store.getClient(b.client_id) : null;
		if (!client) {
			res.status(400).send('Unknown client_id');
			return;
		}
		if (!b.redirect_uri || !client.redirect_uris.includes(b.redirect_uri)) {
			res.status(400).send('redirect_uri not registered for this client');
			return;
		}
		if (!ownerPassword || !b.owner_password || !safeEqual(b.owner_password, ownerPassword)) {
			res.status(401).send('Senha incorreta.');
			return;
		}
		if (!b.code_challenge) {
			res.status(400).send('code_challenge (PKCE) required');
			return;
		}
		const code = randomToken();
		store.saveCode({
			code,
			client_id: client.client_id,
			redirect_uri: b.redirect_uri,
			code_challenge: b.code_challenge,
			scope: b.scope ?? 'mcp',
			expires_at: Date.now() + CODE_TTL * 1000,
		});
		const url = new URL(b.redirect_uri);
		url.searchParams.set('code', code);
		if (b.state) url.searchParams.set('state', b.state);
		res.redirect(302, url.toString());
	});

	// --- token endpoint ---
	app.post('/oauth/token', urlencoded, (req: Request, res: Response) => {
		const b = (req.body ?? {}) as Record<string, string>;
		const grant = b.grant_type;

		if (grant === 'authorization_code') {
			const rec = b.code ? store.takeCode(b.code) : null;
			if (!rec) {
				res.status(400).json({ error: 'invalid_grant', error_description: 'unknown or used code' });
				return;
			}
			if (rec.expires_at < Date.now()) {
				res.status(400).json({ error: 'invalid_grant', error_description: 'code expired' });
				return;
			}
			if (b.client_id && b.client_id !== rec.client_id) {
				res.status(400).json({ error: 'invalid_grant', error_description: 'client mismatch' });
				return;
			}
			if (b.redirect_uri && b.redirect_uri !== rec.redirect_uri) {
				res.status(400).json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
				return;
			}
			if (!b.code_verifier || pkceChallengeFromVerifier(b.code_verifier) !== rec.code_challenge) {
				res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
				return;
			}
			return issueTokens(res, rec.client_id, rec.scope);
		}

		if (grant === 'refresh_token') {
			if (!b.refresh_token) {
				res.status(400).json({ error: 'invalid_request', error_description: 'refresh_token required' });
				return;
			}
			const hash = sha256hex(b.refresh_token);
			const rec = store.getToken(hash);
			if (!rec || rec.type !== 'refresh' || rec.expires_at < Date.now()) {
				res.status(400).json({ error: 'invalid_grant', error_description: 'invalid refresh_token' });
				return;
			}
			store.deleteToken(hash); // rotate
			return issueTokens(res, rec.client_id, rec.scope);
		}

		res.status(400).json({ error: 'unsupported_grant_type' });
	});

	function issueTokens(res: Response, clientId: string, scope: string): void {
		const access = randomToken();
		const refresh = randomToken();
		const now = Date.now();
		store.saveToken({
			token_hash: sha256hex(access),
			type: 'access',
			client_id: clientId,
			scope,
			expires_at: now + ACCESS_TTL * 1000,
		});
		store.saveToken({
			token_hash: sha256hex(refresh),
			type: 'refresh',
			client_id: clientId,
			scope,
			expires_at: now + REFRESH_TTL * 1000,
		});
		res.json({
			access_token: access,
			token_type: 'Bearer',
			expires_in: ACCESS_TTL,
			refresh_token: refresh,
			scope,
		});
	}

	// --- bearer guard for the /mcp endpoint ---
	const requireBearer: RequestHandler = (req, res, next) => {
		const auth = req.headers['authorization'];
		const m = typeof auth === 'string' ? auth.match(/^Bearer\s+(.+)$/i) : null;
		const ok = m ? store.getToken(sha256hex(m[1])) : null;
		if (!ok || ok.type !== 'access' || ok.expires_at < Date.now()) {
			const base = baseUrl(req, publicUrl);
			res
				.status(401)
				.set(
					'WWW-Authenticate',
					`Bearer resource_metadata="${base}/.well-known/oauth-protected-resource"`,
				)
				.json({ error: 'invalid_token' });
			return;
		}
		next();
	};

	return { requireBearer };
}

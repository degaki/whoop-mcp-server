// SQLite-backed implementation of the OAuthStore interface.
// Uses better-sqlite3 (already a project dependency) against the same DB file.

import Database from 'better-sqlite3';
import type { ClientRec, CodeRec, OAuthStore, TokenRec } from './oauth.js';

export function createSqliteStore(dbPath: string): OAuthStore {
	const db = new Database(dbPath);
	db.pragma('journal_mode = WAL');

	db.exec(`
		CREATE TABLE IF NOT EXISTS oauth_clients (
			client_id TEXT PRIMARY KEY,
			client_secret TEXT,
			redirect_uris TEXT NOT NULL,
			created_at INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS oauth_codes (
			code TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			redirect_uri TEXT NOT NULL,
			code_challenge TEXT NOT NULL,
			scope TEXT NOT NULL,
			expires_at INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS oauth_tokens (
			token_hash TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			client_id TEXT NOT NULL,
			scope TEXT NOT NULL,
			expires_at INTEGER NOT NULL
		);
	`);

	return {
		saveClient(c: ClientRec): void {
			db.prepare(
				'INSERT OR REPLACE INTO oauth_clients (client_id, client_secret, redirect_uris, created_at) VALUES (?, ?, ?, ?)',
			).run(c.client_id, c.client_secret, JSON.stringify(c.redirect_uris), c.created_at);
		},
		getClient(id: string): ClientRec | null {
			const row = db.prepare('SELECT * FROM oauth_clients WHERE client_id = ?').get(id) as
				| { client_id: string; client_secret: string | null; redirect_uris: string; created_at: number }
				| undefined;
			if (!row) return null;
			return {
				client_id: row.client_id,
				client_secret: row.client_secret,
				redirect_uris: JSON.parse(row.redirect_uris) as string[],
				created_at: row.created_at,
			};
		},
		saveCode(c: CodeRec): void {
			db.prepare(
				'INSERT OR REPLACE INTO oauth_codes (code, client_id, redirect_uri, code_challenge, scope, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
			).run(c.code, c.client_id, c.redirect_uri, c.code_challenge, c.scope, c.expires_at);
		},
		takeCode(code: string): CodeRec | null {
			const row = db.prepare('SELECT * FROM oauth_codes WHERE code = ?').get(code) as CodeRec | undefined;
			if (!row) return null;
			db.prepare('DELETE FROM oauth_codes WHERE code = ?').run(code);
			return row;
		},
		saveToken(t: TokenRec): void {
			db.prepare(
				'INSERT OR REPLACE INTO oauth_tokens (token_hash, type, client_id, scope, expires_at) VALUES (?, ?, ?, ?, ?)',
			).run(t.token_hash, t.type, t.client_id, t.scope, t.expires_at);
		},
		getToken(hash: string): TokenRec | null {
			const row = db.prepare('SELECT * FROM oauth_tokens WHERE token_hash = ?').get(hash) as
				| TokenRec
				| undefined;
			return row ?? null;
		},
		deleteToken(hash: string): void {
			db.prepare('DELETE FROM oauth_tokens WHERE token_hash = ?').run(hash);
		},
	};
}

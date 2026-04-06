/**
 * ChatGPT Plus/Pro OAuth Authentication for OpenClaude
 *
 * Implements OAuth 2.0 PKCE flow and Device Code flow to authenticate
 * with ChatGPT subscriptions, allowing usage of Codex models without
 * a separate API key.
 *
 * Based on the OpenCode project's codex auth plugin approach.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { execSync } from 'node:child_process'
import { homedir } from 'node:os'
import { join, dirname } from 'node:path'

const CLIENT_ID = 'app_EMoamEEZ73f0CkXaXp7hrann'
const ISSUER = 'https://auth.openai.com'
const OAUTH_PORT = 1455
const OAUTH_POLLING_SAFETY_MARGIN_MS = 3000

// ─── PKCE Helpers ────────────────────────────────────────────────────────────

function generateRandomString(length: number): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~'
  const bytes = crypto.getRandomValues(new Uint8Array(length))
  return Array.from(bytes)
    .map((b) => chars[b % chars.length])
    .join('')
}

function base64UrlEncode(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  const binary = String.fromCharCode(...bytes)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function generatePKCE(): Promise<{ verifier: string; challenge: string }> {
  const verifier = generateRandomString(43)
  const encoder = new TextEncoder()
  const hash = await crypto.subtle.digest('SHA-256', encoder.encode(verifier))
  return { verifier, challenge: base64UrlEncode(hash) }
}

function generateState(): string {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)).buffer as ArrayBuffer)
}

// ─── JWT Parsing ────────��────────────────────────────────────────────────────

interface IdTokenClaims {
  chatgpt_account_id?: string
  organizations?: Array<{ id: string }>
  'https://api.openai.com/auth'?: {
    chatgpt_account_id?: string
  }
}

function parseJwtClaims(token: string): IdTokenClaims | undefined {
  const parts = token.split('.')
  if (parts.length !== 3) return undefined
  try {
    const normalized = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4)
    return JSON.parse(Buffer.from(padded, 'base64').toString('utf8'))
  } catch {
    return undefined
  }
}

function extractAccountId(tokens: TokenResponse): string | undefined {
  for (const tokenStr of [tokens.id_token, tokens.access_token]) {
    if (!tokenStr) continue
    const claims = parseJwtClaims(tokenStr)
    if (!claims) continue
    const id =
      claims.chatgpt_account_id ||
      claims['https://api.openai.com/auth']?.chatgpt_account_id ||
      claims.organizations?.[0]?.id
    if (id) return id
  }
  return undefined
}

// ─── Token Types ─────────────────────────────────���───────────────────────────

interface TokenResponse {
  id_token?: string
  access_token: string
  refresh_token: string
  expires_in?: number
}

export interface CodexOAuthTokens {
  access_token: string
  refresh_token: string
  account_id?: string
  expires_at: number
}

// ─── Token Storage ───────────────────────────────────────────────────────────

function getAuthFilePath(): string {
  const codexHome = process.env.CODEX_HOME?.trim()
  if (codexHome) return join(codexHome, 'auth.json')
  return join(homedir(), '.codex', 'auth.json')
}

export function loadCodexOAuthTokens(): CodexOAuthTokens | null {
  const filePath = getAuthFilePath()
  if (!existsSync(filePath)) return null

  try {
    const data = JSON.parse(readFileSync(filePath, 'utf8'))
    if (!data || typeof data !== 'object') return null

    const accessToken = data.access_token || data.accessToken
    const refreshToken = data.refresh_token || data.refreshToken
    if (!accessToken || !refreshToken) return null

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      account_id: data.account_id || data.accountId,
      expires_at: data.expires_at || data.expiresAt || 0,
    }
  } catch {
    return null
  }
}

function saveCodexOAuthTokens(tokens: CodexOAuthTokens): void {
  const filePath = getAuthFilePath()
  const dir = dirname(filePath)
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 })
  }

  writeFileSync(
    filePath,
    JSON.stringify(tokens, null, 2),
    { encoding: 'utf8', mode: 0o600 },
  )
}

// ─── Token Exchange & Refresh ─────────────��──────────────────────────────────

async function exchangeCodeForTokens(
  code: string,
  redirectUri: string,
  codeVerifier: string,
): Promise<TokenResponse> {
  const response = await fetch(`${ISSUER}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: CLIENT_ID,
      code_verifier: codeVerifier,
    }).toString(),
  })
  if (!response.ok) {
    throw new Error(`Token exchange failed: ${response.status}`)
  }
  return response.json()
}

async function refreshAccessToken(refreshToken: string): Promise<TokenResponse> {
  const response = await fetch(`${ISSUER}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
    }).toString(),
  })
  if (!response.ok) {
    throw new Error(`Token refresh failed: ${response.status}`)
  }
  return response.json()
}

/**
 * Ensures the stored Codex OAuth tokens are valid.
 * If expired, refreshes them automatically.
 * Returns null if no OAuth tokens are stored.
 */
export async function ensureValidCodexOAuthTokens(): Promise<CodexOAuthTokens | null> {
  const tokens = loadCodexOAuthTokens()
  if (!tokens) return null

  // Check if token is still valid (with 60s buffer)
  if (tokens.expires_at > Date.now() + 60_000) {
    return tokens
  }

  // Token expired or about to expire — refresh it
  try {
    const refreshed = await refreshAccessToken(tokens.refresh_token)
    const accountId = extractAccountId(refreshed) || tokens.account_id

    const newTokens: CodexOAuthTokens = {
      access_token: refreshed.access_token,
      refresh_token: refreshed.refresh_token || tokens.refresh_token,
      account_id: accountId,
      expires_at: Date.now() + (refreshed.expires_in ?? 3600) * 1000,
    }

    saveCodexOAuthTokens(newTokens)
    return newTokens
  } catch {
    // Refresh failed — tokens are invalid
    return null
  }
}

// ─── HTML Templates ───────────────���──────────────────────────────────────────

const HTML_SUCCESS = `<!doctype html>
<html><head><title>OpenClaude - Authorization Successful</title>
<style>
body{font-family:system-ui,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#131010;color:#f1ecec}
.c{text-align:center;padding:2rem}h1{color:#4ade80;margin-bottom:1rem}p{color:#b7b1b1}
</style></head><body><div class="c"><h1>Authorization Successful</h1>
<p>You can close this window and return to OpenClaude.</p></div>
<script>setTimeout(()=>window.close(),2000)</script></body></html>`

const HTML_ERROR = (error: string) => `<!doctype html>
<html><head><title>OpenClaude - Authorization Failed</title>
<style>
body{font-family:system-ui,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#131010;color:#f1ecec}
.c{text-align:center;padding:2rem}h1{color:#fc533a;margin-bottom:1rem}p{color:#b7b1b1}
.e{color:#ff917b;font-family:monospace;margin-top:1rem;padding:1rem;background:#3c140d;border-radius:.5rem}
</style></head><body><div class="c"><h1>Authorization Failed</h1>
<p>An error occurred during authorization.</p><div class="e">${error}</div></div></body></html>`

// ─── Browser-based OAuth PKCE Flow ───────��──────────────────────────────────

/**
 * Performs the browser-based OAuth PKCE flow.
 * Opens the user's browser for ChatGPT login, receives the callback on localhost.
 *
 * @returns The saved OAuth tokens
 */
export async function performBrowserOAuthLogin(): Promise<CodexOAuthTokens> {
  const pkce = await generatePKCE()
  const state = generateState()
  const redirectUri = `http://localhost:${OAUTH_PORT}/auth/callback`

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: redirectUri,
    scope: 'openid profile email offline_access',
    code_challenge: pkce.challenge,
    code_challenge_method: 'S256',
    id_token_add_organizations: 'true',
    codex_cli_simplified_flow: 'true',
    state,
    originator: 'openclaude',
  })

  const authUrl = `${ISSUER}/oauth/authorize?${params.toString()}`

  return new Promise<CodexOAuthTokens>((resolve, reject) => {
    const timeout = setTimeout(() => {
      server.close()
      reject(new Error('OAuth timeout — authorization took too long (5 minutes)'))
    }, 5 * 60 * 1000)

    const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
      const url = new URL(req.url ?? '/', `http://localhost:${OAUTH_PORT}`)

      if (url.pathname === '/auth/callback') {
        const error = url.searchParams.get('error')
        const errorDescription = url.searchParams.get('error_description')
        const code = url.searchParams.get('code')
        const returnedState = url.searchParams.get('state')

        if (error) {
          const msg = errorDescription || error
          res.writeHead(200, { 'Content-Type': 'text/html' })
          res.end(HTML_ERROR(msg))
          clearTimeout(timeout)
          server.close()
          reject(new Error(msg))
          return
        }

        if (!code) {
          res.writeHead(400, { 'Content-Type': 'text/html' })
          res.end(HTML_ERROR('Missing authorization code'))
          clearTimeout(timeout)
          server.close()
          reject(new Error('Missing authorization code'))
          return
        }

        if (returnedState !== state) {
          res.writeHead(400, { 'Content-Type': 'text/html' })
          res.end(HTML_ERROR('Invalid state — potential CSRF'))
          clearTimeout(timeout)
          server.close()
          reject(new Error('Invalid state parameter'))
          return
        }

        res.writeHead(200, { 'Content-Type': 'text/html' })
        res.end(HTML_SUCCESS)

        try {
          const tokenResponse = await exchangeCodeForTokens(code, redirectUri, pkce.verifier)
          const accountId = extractAccountId(tokenResponse)

          const tokens: CodexOAuthTokens = {
            access_token: tokenResponse.access_token,
            refresh_token: tokenResponse.refresh_token,
            account_id: accountId,
            expires_at: Date.now() + (tokenResponse.expires_in ?? 3600) * 1000,
          }

          saveCodexOAuthTokens(tokens)
          clearTimeout(timeout)
          server.close()
          resolve(tokens)
        } catch (err) {
          clearTimeout(timeout)
          server.close()
          reject(err)
        }
        return
      }

      res.writeHead(404)
      res.end('Not found')
    })

    server.listen(OAUTH_PORT, () => {
      // Open the browser
      try {
        const platform = process.platform
        if (platform === 'win32') execSync(`start "" "${authUrl}"`, { stdio: 'ignore' })
        else if (platform === 'darwin') execSync(`open "${authUrl}"`, { stdio: 'ignore' })
        else execSync(`xdg-open "${authUrl}"`, { stdio: 'ignore' })
      } catch {
        // Browser open failed — user will need to visit the URL manually
      }
    })

    server.on('error', (err) => {
      clearTimeout(timeout)
      reject(new Error(`Failed to start OAuth server on port ${OAUTH_PORT}: ${err.message}`))
    })
  })
}

// ─── Device Code Flow (Headless) ─��───────────────────────────────────────────

export interface DeviceCodeInfo {
  userCode: string
  verificationUrl: string
}

/**
 * Performs the headless device code flow.
 * Returns the device code and URL for the user to visit.
 * Call `pollDeviceCodeLogin()` to wait for completion.
 */
export async function initiateDeviceCodeLogin(): Promise<{
  info: DeviceCodeInfo
  poll: () => Promise<CodexOAuthTokens>
}> {
  const deviceResponse = await fetch(`${ISSUER}/api/accounts/deviceauth/usercode`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'openclaude',
    },
    body: JSON.stringify({ client_id: CLIENT_ID }),
  })

  if (!deviceResponse.ok) {
    throw new Error(`Failed to initiate device authorization: ${deviceResponse.status}`)
  }

  const deviceData = (await deviceResponse.json()) as {
    device_auth_id: string
    user_code: string
    interval: string
  }

  const interval = Math.max(parseInt(deviceData.interval) || 5, 1) * 1000

  const info: DeviceCodeInfo = {
    userCode: deviceData.user_code,
    verificationUrl: `${ISSUER}/codex/device`,
  }

  const poll = async (): Promise<CodexOAuthTokens> => {
    while (true) {
      const response = await fetch(`${ISSUER}/api/accounts/deviceauth/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'openclaude',
        },
        body: JSON.stringify({
          device_auth_id: deviceData.device_auth_id,
          user_code: deviceData.user_code,
        }),
      })

      if (response.ok) {
        const data = (await response.json()) as {
          authorization_code: string
          code_verifier: string
        }

        const tokenResponse = await fetch(`${ISSUER}/oauth/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            code: data.authorization_code,
            redirect_uri: `${ISSUER}/deviceauth/callback`,
            client_id: CLIENT_ID,
            code_verifier: data.code_verifier,
          }).toString(),
        })

        if (!tokenResponse.ok) {
          throw new Error(`Token exchange failed: ${tokenResponse.status}`)
        }

        const tokens: TokenResponse = await tokenResponse.json()
        const accountId = extractAccountId(tokens)

        const oauthTokens: CodexOAuthTokens = {
          access_token: tokens.access_token,
          refresh_token: tokens.refresh_token,
          account_id: accountId,
          expires_at: Date.now() + (tokens.expires_in ?? 3600) * 1000,
        }

        saveCodexOAuthTokens(oauthTokens)
        return oauthTokens
      }

      if (response.status !== 403 && response.status !== 404) {
        throw new Error(`Device code polling failed: ${response.status}`)
      }

      await new Promise((r) => setTimeout(r, interval + OAUTH_POLLING_SAFETY_MARGIN_MS))
    }
  }

  return { info, poll }
}

/**
 * Check if OAuth tokens exist and are (or can be made) valid.
 */
export function hasCodexOAuthTokens(): boolean {
  return loadCodexOAuthTokens() !== null
}

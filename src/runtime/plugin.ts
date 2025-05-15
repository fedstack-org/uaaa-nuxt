import { useDebounceFn, useLocalStorage } from '@vueuse/core'
import { computed } from 'vue'
import debug from 'debug'
import { defineNuxtPlugin, useRuntimeConfig } from '#imports'

const logger = debug('uaaa')

type OpenIdConfig = {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  userinfo_endpoint: string
  end_session_endpoint: string
  jwks_uri: string
  response_types_supported: string[]
  subject_types_supported: string[]
  id_token_signing_alg_values_supported: string[]
}

type Token = {
  iss: string
  sub: string
  aud: string
  client_id: string
  sid: string
  jti: string
  perm: string[]
  level: number
  exp: number
  iat: number
}

type IClientToken = {
  token: string
  refreshToken?: string
  decoded: Token
  expireSoon?: boolean
}

const serializer = {
  read: JSON.parse,
  write: JSON.stringify
}

const options = { serializer }

const generateCodeVerifier = () => {
  const array = new Uint8Array(32)
  window.crypto.getRandomValues(array)
  return Array.from(array, (byte) => String.fromCharCode(byte))
    .join('')
    .replace(/[^\w-]/g, '')
    .substring(0, 43)
}

// Generate code challenge from verifier using SHA-256
const generateCodeChallenge = async (verifier: string) => {
  const encoder = new TextEncoder()
  const data = encoder.encode(verifier)
  const hash = await window.crypto.subtle.digest('SHA-256', data)
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

interface ILoginState {
  codeVerifier: string
  state: string
  redirect: string
}

export interface IStartLoginOptions {
  permissions?: Array<string | { path: string; optional?: boolean }>
  additionalParams?: Record<string, string>
  callback?: string
}

export interface ILogoutOptions {
  callback?: string
}

export class AuthManager {
  uaaaConfig
  cachedOpenidConfig
  refreshingOpenidConfig?: Promise<OpenIdConfig>

  tokens
  cachedTokens
  idToken
  securityLevel
  effectiveToken
  userId
  appId
  isLoggedIn
  refreshTokensDebounced
  tokensInit
  loginState

  constructor() {
    const runtimeConfig = useRuntimeConfig()
    this.uaaaConfig = runtimeConfig.public.uaaa
    this.cachedOpenidConfig = useLocalStorage<OpenIdConfig | null>('openid_config', null, options)
    this.idToken = useLocalStorage<string>('id_token', '')

    this.tokens = useLocalStorage<IClientToken[]>('tokens', [], options)
    this.cachedTokens = useLocalStorage<IClientToken[]>('cached_tokens', [], options)
    this.securityLevel = useLocalStorage<number>('level', -1, options)
    this.effectiveToken = computed<IClientToken | null>(
      () => this.tokens.value[this.securityLevel.value] ?? null
    )
    this.appId = computed(() => this.effectiveToken.value?.decoded.client_id ?? '')
    this.userId = computed(() => this.effectiveToken.value?.decoded.sub ?? '')

    this.isLoggedIn = computed(() => this.securityLevel.value !== -1)
    this.refreshTokensDebounced = useDebounceFn(() => this._lockAndRefreshTokens(), 1000)
    this.tokensInit = this._lockAndRefreshTokens()
    this.loginState = useLocalStorage<ILoginState | null>('login_state', null, options)
  }

  async loadOpenidConfig() {
    this.refreshingOpenidConfig ??= this._loadOpenidConfig()
    return this.cachedOpenidConfig.value ?? this.refreshingOpenidConfig
  }

  private async _loadOpenidConfig() {
    const discovery = new URL('.well-known/openid-configuration', this.uaaaConfig.issuer)
    const resp = await fetch(discovery)
    const config = await resp.json()
    this.cachedOpenidConfig.value = config
    return config as OpenIdConfig
  }

  private async _refreshTokenFor(
    level: number,
    target = this.appId.value,
    force = false,
    now = Date.now()
  ) {
    const log = logger.extend(`refreshTokenFor`)
    const token = this.tokens.value[level]
    if (!token) return
    const remaining = token.decoded.exp * 1000 - now
    const lifetime = (token.decoded.exp - token.decoded.iat) * 1000
    if (!force && remaining > lifetime / 2) return
    log(`Refreshing token level=${level} target=${target}`)
    if (token.refreshToken && !token.expireSoon) {
      try {
        const { token_endpoint } = await this.loadOpenidConfig()
        const data = new URLSearchParams()
        data.set('grant_type', 'refresh_token')
        data.set('refresh_token', token.refreshToken)
        data.set('client_id', this.uaaaConfig.clientAppId)
        data.set('target_app_id', target)
        const resp = await fetch(token_endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: data
        })
        if (!resp.ok) throw new Error(`Failed to refresh token: ${resp.status}`)
        const { access_token, refresh_token } = await resp.json()
        const oldExp = token.decoded.exp
        const oldIat = token.decoded.iat
        this.cachedTokens.value.push(this.tokens.value[level])
        this.tokens.value[level] = {
          token: access_token,
          refreshToken: refresh_token,
          decoded: AuthManager.parseJwt(access_token)
        }
        if (now - oldIat * 1000 >= 3_000 && this.tokens.value[level].decoded.exp <= oldExp) {
          this.tokens.value[level].expireSoon = true
        }
        log(`Token level=${level} refreshed to ${target}`)
        return
      } catch (err) {
        delete this.tokens.value[level].refreshToken
        log(`Token level=${level} failed to refresh: ${err}`)
      }
    }
    // Token not refreshed, check if it is expired
    if (remaining < 3 * 1000) {
      log(`Token level=${level} dropped remaining=${remaining}ms`)
      // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
      delete this.tokens.value[level]
    }
  }

  private async _lockAndRefreshTokenFor(
    level: number,
    target?: string,
    force?: boolean,
    now?: number
  ) {
    return navigator.locks.request(`tokens`, () => this._refreshTokenFor(level, target, force, now))
  }

  private async _refreshTokens() {
    const log = logger.extend(`refreshTokens`)
    if (this.securityLevel.value === null) return
    const now = Date.now()
    console.group(`[Auth] Refreshing tokens at ${now}`)
    await Promise.all(
      Array.from({ length: this.securityLevel.value + 1 }, (_, i) =>
        this._refreshTokenFor(i, undefined, undefined, now)
      )
    )
    log(`Calculating Security Level`)
    const level = this.tokens.value.reduce((acc, token, i) => {
      if (token && token.decoded.exp * 1000 > now) return i
      return acc
    }, -1)
    log(`Security Level is ${level}`)
    this.securityLevel.value = level
    console.groupEnd()
  }

  private async _lockAndRefreshTokens() {
    return navigator.locks.request(`tokens`, () => this._refreshTokens())
  }

  // private async _downgradeTokenFrom(level: SecurityLevel) {
  //   console.log(`[API] Downgrading token to level ${level}`)
  //   try {
  //     const resp = await this.session.downgrade.$post({ json: { targetLevel: level } })
  //     await this.checkResponse(resp)
  //     const {
  //       token: { token, refreshToken }
  //     } = await resp.json()
  //     this.tokens.value[level] = { token, refreshToken, decoded: ApiManager.parseJwt(token) }
  //   } catch (err) {
  //     console.log(`[API] Token downgrade failed: ${this._formatError(err)}`)
  //   }
  // }

  /**
   * Fill token store
   */
  private async _applyToken(token: string, refreshToken?: string) {
    const decoded = AuthManager.parseJwt(token)
    const { jti, level } = decoded
    console.group(`[Auth] Applying token ${jti}`)
    this.tokens.value[level] = { token, refreshToken, decoded }
    this.securityLevel.value = level
    // await Promise.all(
    //   Array.from({ length: level }, (_, i) => this._downgradeTokenFrom(i as SecurityLevel))
    // )
    console.groupEnd()
  }

  private async _lockAndUpdateCachedTokens() {
    const log = logger.extend(`updateCachedTokens`)
    await navigator.locks.request(`tokens`, async () => {
      log(`Updating cached tokens`)
      const now = Date.now()
      this.cachedTokens.value = this.cachedTokens.value.filter((token) => {
        const remaining = token.decoded.exp * 1000 - now
        if (remaining < 3 * 1000) {
          log(`Cached token dropped remaining=${remaining}ms`)
          return false
        }
        return true
      })
    })
    return this.cachedTokens.value
  }

  async getAuthToken(appId: string = this.appId.value) {
    const log = logger.extend(`getAuthToken`)
    await this.tokensInit
    if ((this.effectiveToken.value?.decoded.exp ?? 0) * 1000 - Date.now() < 3000) {
      log(`force refresh current token`)
      await this._lockAndRefreshTokens()
    }
    this.refreshTokensDebounced()
    if (this.effectiveToken.value?.decoded.aud === appId) {
      return this.effectiveToken.value
    }
    // Find cached token
    const cachedTokens = await this._lockAndUpdateCachedTokens()
    const cachedToken = cachedTokens.find(
      (token) => token.decoded.aud === appId && token.decoded.level === this.securityLevel.value
    )
    if (cachedToken) {
      return cachedToken
    }
    // Refresh the current token
    log(`force refresh current token to ${appId}`)
    await this._lockAndRefreshTokenFor(this.securityLevel.value, appId, true)
    return this.effectiveToken.value
  }

  async startLogin(redirect: string, options: IStartLoginOptions = {}) {
    const log = logger.extend(`startLogin`)
    console.group(`[Auth] Starting login`)
    const permissions = options.permissions ?? [
      `uperm://{{server}}/**`,
      `uperm://{{issuer}}/session/claim`
    ]
    const mappedPermissionScopes = permissions.map((p) => {
      const { path, optional } = typeof p === 'string' ? { path: p } : p
      const schema = optional ? 'uperm+optional' : 'uperm'
      const interpolatedPath = path
        .replaceAll('{{client}}', this.uaaaConfig.clientAppId)
        .replaceAll('{{server}}', this.uaaaConfig.serverAppId)
        .replaceAll('{{issuer}}', this.uaaaConfig.issuerAppId)
      return `${schema}://${interpolatedPath}`
    })
    log(`Mapped permissions: ${mappedPermissionScopes.join(', ')}`)

    const { authorization_endpoint } = await this.loadOpenidConfig()
    const url = new URL(authorization_endpoint)
    url.searchParams.set('client_id', this.uaaaConfig.clientAppId)
    url.searchParams.set(
      'scope',
      ['openid', 'profile', 'email', ...mappedPermissionScopes].map(encodeURIComponent).join(' ')
    )
    url.searchParams.set('response_type', 'code')
    url.searchParams.set('confidential', '0')
    const callback = options.callback ?? new URL('/auth/callback', location.origin).href
    url.searchParams.set('redirect_uri', callback)
    for (const [k, v] of Object.entries(options.additionalParams ?? {})) {
      url.searchParams.set(k, v)
    }

    // Generate and store code verifier, and create code challenge
    const codeVerifier = generateCodeVerifier()
    const codeChallenge = await generateCodeChallenge(codeVerifier)
    const state = Math.random().toString(36).slice(2)

    // Add PKCE parameters
    url.searchParams.set('code_challenge', codeChallenge)
    url.searchParams.set('code_challenge_method', 'S256')
    url.searchParams.set('state', state)
    log(`Redirect URL: ${url.href}`)
    console.groupEnd()
    this.loginState.value = { codeVerifier, state, redirect }
    return url.href
  }

  async finishLogin(
    code: string,
    state: string,
    activate?: (accessToken: string) => Promise<void>
  ) {
    const loginState = this.loginState.value
    if (!loginState) throw new Error(`Login state not found`)
    if (state !== loginState.state) throw new Error(`Invalid state`)
    const { token_endpoint } = await this.loadOpenidConfig()
    const data = new URLSearchParams()
    data.set('grant_type', 'authorization_code')
    data.set('code', code)
    data.set('client_id', this.uaaaConfig.clientAppId)
    data.set('redirect_uri', new URL('/auth/callback', location.origin).href)
    data.set('code_verifier', loginState.codeVerifier)
    const resp = await fetch(token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: data
    })
    if (!resp.ok) throw new Error(`Failed to get token: ${resp.status}`)
    const { access_token, refresh_token, id_token } = await resp.json()
    this.idToken.value = id_token
    await activate?.(access_token)
    await this._applyToken(access_token, refresh_token)
    return loginState.redirect
  }

  async logout(options: ILogoutOptions = {}) {
    const log = logger.extend(`logout`)
    log(`Will logout`)
    const idToken = this.idToken.value
    const { end_session_endpoint } = await this.loadOpenidConfig()
    await navigator.locks.request(`tokens`, async () => {
      log(`Logging out`)
      this.tokens.value = []
      this.cachedTokens.value = []
      this.securityLevel.value = -1
      this.idToken.value = ''
    })
    const form = document.createElement('form')
    form.method = 'POST'
    form.action = end_session_endpoint
    form.target = '_self'
    form.innerHTML += `<input type="hidden" name="id_token_hint" value="${idToken}"/>`
    form.innerHTML += `<input type="hidden" name="client_id" value="${this.uaaaConfig.clientAppId}"/>`
    const callback = options.callback ?? new URL('/auth/logout', location.origin).href
    form.innerHTML += `<input type="hidden" name="post_logout_redirect_uri" value="${callback}"/>`
    document.body.appendChild(form)
    form.submit()
  }

  static parseJwt(token: string) {
    return JSON.parse(atob(token.split('.')[1])) as Token
  }
}

export default defineNuxtPlugin(() => {
  const auth = new AuthManager()
  return {
    provide: { auth }
  }
})

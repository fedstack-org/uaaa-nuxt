import { useDebounceFn, useLocalStorage } from '@vueuse/core'
import { computed } from 'vue'
import { defineNuxtPlugin, useRuntimeConfig } from '#imports'

type OpenIdConfig = {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  userinfo_endpoint: string
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

export class AuthManager {
  uaaaConfig
  cachedOpenidConfig
  refreshingOpenidConfig?: Promise<OpenIdConfig>

  token
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
    this.token = useLocalStorage<IClientToken | null>('token', null, options)
    this.userId = computed(() => this.token.value?.decoded.sub ?? '')
    this.appId = computed(() => this.token.value?.decoded.client_id ?? '')
    this.isLoggedIn = computed(() => !!this.token.value)
    this.refreshTokensDebounced = useDebounceFn(() => this._lockAndRefreshToken(), 1000)
    this.tokensInit = this._lockAndRefreshToken()
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

  private async _refreshToken(force = false) {
    const now = Date.now()
    const token = this.token.value
    if (!token) return
    const remaining = token.decoded.exp * 1000 - now
    const lifetime = (token.decoded.exp - token.decoded.iat) * 1000
    if (!force && remaining > lifetime / 2) return
    console.log(`[Auth] Refreshing token`)
    if (token.refreshToken && !token.expireSoon) {
      try {
        const { token_endpoint } = await this.loadOpenidConfig()
        const data = new URLSearchParams()
        data.set('grant_type', 'refresh_token')
        data.set('refresh_token', token.refreshToken)
        data.set('client_id', this.uaaaConfig.clientAppId)
        data.set('target_app_id', this.uaaaConfig.issuerAppId)
        const resp = await fetch(token_endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: data
        })
        if (!resp.ok) throw new Error(`Failed to refresh token: ${resp.status}`)
        const { access_token, refresh_token } = await resp.json()
        const oldExp = token.decoded.exp
        const oldIat = token.decoded.iat
        this.token.value = {
          token: access_token,
          refreshToken: refresh_token,
          decoded: AuthManager.parseJwt(access_token)
        }
        if (now - oldIat * 1000 >= 3_000 && this.token.value.decoded.exp <= oldExp) {
          this.token.value.expireSoon = true
        }
        console.log(`[Auth] Token refreshed`)
        return
      } catch (err) {
        delete this.token.value?.refreshToken
        console.log(`[Auth] Token failed to refresh: ${err}`)
      }
    }
    // Token not refreshed, check if it is expired
    if (remaining < 3 * 1000) {
      console.log(`[Auth] Token dropped remaining=${remaining}ms`)
      this.token.value = null
    }
  }

  private async _lockAndRefreshToken(force = false) {
    return navigator.locks.request(`tokens`, () => this._refreshToken(force))
  }

  /**
   * Fill token store
   */
  private async _applyToken(token: string, refreshToken?: string) {
    const decoded = AuthManager.parseJwt(token)
    const { jti } = decoded
    console.group(`[Auth] Applying token ${jti}`)
    this.token.value = { token, refreshToken, decoded }
    console.groupEnd()
  }

  async getAuthToken() {
    await this.tokensInit
    if ((this.token.value?.decoded.exp ?? 0) * 1000 - Date.now() < 3000) {
      await this._lockAndRefreshToken()
    }
    this.refreshTokensDebounced()
    return this.token.value
  }

  async getHeaders() {
    const headers: Record<string, string> = Object.create(null)
    const token = await this.getAuthToken()
    if (token) headers.Authorization = `Bearer ${token.token}`
    return headers
  }

  async startLogin(redirect: string) {
    const { authorization_endpoint } = await this.loadOpenidConfig()
    const url = new URL(authorization_endpoint)
    url.searchParams.set('client_id', this.uaaaConfig.clientAppId)
    url.searchParams.set(
      'scope',
      [
        'openid',
        'profile',
        'email',
        `uperm://${this.uaaaConfig.serverAppId}/**`,
        `uperm://${this.uaaaConfig.issuerAppId}/session/claim`
        // `uperm://${this.uaaaConfig.issuerAppId}/session/slient_authorize`
      ]
        .map(encodeURIComponent)
        .join(' ')
    )
    url.searchParams.set('response_type', 'code')
    url.searchParams.set('confidential', '0')
    url.searchParams.set('redirect_uri', new URL('/auth/callback', location.origin).href)
    // url.searchParams.set('preferType', 'iaaa')
    // url.searchParams.set('nonInteractive', 'true')

    // Generate and store code verifier, and create code challenge
    const codeVerifier = generateCodeVerifier()
    const codeChallenge = await generateCodeChallenge(codeVerifier)
    const state = Math.random().toString(36).slice(2)

    // Add PKCE parameters
    url.searchParams.set('code_challenge', codeChallenge)
    url.searchParams.set('code_challenge_method', 'S256')
    url.searchParams.set('state', state)
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
    const { access_token, refresh_token } = await resp.json()
    await activate?.(access_token)
    await this._applyToken(access_token, refresh_token)
    await this._refreshToken(true)
    return loginState.redirect
  }

  async logout() {
    console.log(`[Auth] Will logout`)
    await navigator.locks.request(`tokens`, async () => {
      console.log(`[Auth] Logging out`)
      this.token.value = null
    })
    window.open('/', '_self')
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

import type { H3Event } from 'h3'
import { eventHandler, getQuery, sendRedirect, getRequestURL } from 'h3'
import { withQuery } from 'ufo'
import { defu } from 'defu'
import { FetchError, $fetch } from 'ofetch'
import { snakeCase, upperFirst } from 'scule'
import { useRuntimeConfig, createError } from '#imports'
import type { OAuthConfig, OAuthProvider, OnError } from '#auth-utils'

export interface OAuthLinuxdoConfig {
  /**
   * Linuxdo OAuth Client ID
   * @default process.env.NUXT_OAUTH_LINUXDO_CLIENT_ID
   */
  clientId?: string
  /**
   * Linuxdo OAuth Client Secret
   * @default process.env.NUXT_OAUTH_LINUXDO_CLIENT_SECRET
   */
  clientSecret?: string
  /**
   * Linuxdo OAuth Issuer
   * @default process.env.NUXT_OAUTH_LINUXDO_DOMAIN
   */
  domain?: string
  /**
   * Linuxdo OAuth Audience
   * @default process.env.NUXT_OAUTH_LINUXDO_AUDIENCE
   */
  audience?: string
  /**
   * Linuxdo OAuth Scope
   * @default []
   * @see https://auth0.com/docs/get-started/apis/scopes/openid-connect-scopes
   * @example ['openid']
   */
  scope?: string[]
  /**
   * Require email from user, adds the ['email'] scope if not present
   * @default false
   */
  emailRequired?: boolean
  /**
   * Maximum Authentication Age. If the elapsed time is greater than this value, the OP must attempt to actively re-authenticate the end-user.
   * @default 0
   * @see https://auth0.com/docs/authenticate/login/max-age-reauthentication
   */
  maxAge?: number
  /**
   * Login connection. If no connection is specified, it will redirect to the standard Linuxdo login page and show the Login Widget.
   * @default ''
   * @see https://auth0.com/docs/api/authentication#social
   * @example 'github'
   */
  connection?: string
  /**
   * Extra authorization parameters to provide to the authorization URL
   * @see https://auth0.com/docs/api/authentication#social
   * @example { display: 'popup' }
   */
  authorizationParams?: Record<string, string>
  /**
   * Redirect URL to to allow overriding for situations like prod failing to determine public hostname
   * @default process.env.NUXT_OAUTH_LINUXDO_REDIRECT_URL or current URL
   */
  redirectURL?: string
}

export function oauthLinuxdoEventHandler({ config, onSuccess, onError }: OAuthConfig<OAuthLinuxdoConfig>) {
  return eventHandler(async (event: H3Event) => {
    config = defu(config, useRuntimeConfig(event).oauth?.linuxdo, {
      authorizationParams: {},
    }) as OAuthLinuxdoConfig

    if (!config.clientId || !config.clientSecret || !config.domain) {
      return handleMissingConfiguration(event, 'linuxdo', ['clientId', 'clientSecret', 'domain'], onError)
    }
    const authorizationURL = `https://${config.domain}/oauth2/authorize`
    const tokenURL = `https://${config.domain}/oauth2/token`

    const query = getQuery<{ code?: string }>(event)
    const redirectURL = config.redirectURL || getOAuthRedirectURL(event)

    if (!query.code) {
      config.scope = config.scope || ['openid', 'offline_access']
      if (config.emailRequired && !config.scope.includes('email')) {
        config.scope.push('email')
      }
      // Redirect to Linuxdo Oauth page
      return sendRedirect(
        event,
        withQuery(authorizationURL as string, {
          response_type: 'code',
          client_id: config.clientId,
          redirect_uri: redirectURL,
          scope: config.scope.join(' '),
          audience: config.audience || '',
          max_age: config.maxAge || 0,
          connection: config.connection || '',
          ...config.authorizationParams,
        }),
      )
    }

    const tokens = await requestAccessToken(tokenURL as string, {
      headers: {
        Authorization: 'Basic ' + Buffer.from(`${config.clientId}:${config.clientSecret}`).toString('base64'),
      },
      body: {
        grant_type: 'authorization_code',
        redirect_uri: redirectURL,
        code: query.code,
      },
    }).catch((error) => {
        if (!onError) throw error
        return onError(event, error)
    })

    if (tokens.error) {
      return handleAccessTokenErrorResponse(event, 'linuxdo', tokens, onError)
    }

    const accessToken = tokens.access_token

    // TODO: improve typing
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const user: any = await $fetch(`https://${config.domain}/api/user`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    })

    return onSuccess(event, {
      tokens,
      user,
    })
  })
}

export function getOAuthRedirectURL(event: H3Event): string {
  const requestURL = getRequestURL(event)

  return `${requestURL.protocol}//${requestURL.host}${requestURL.pathname}`
}

/**
 * Request an access token body.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
 */
interface RequestAccessTokenBody {
  grant_type: 'authorization_code'
  code: string
  redirect_uri: string
}

interface RequestAccessTokenOptions {
  body?: RequestAccessTokenBody
  params?: Record<string, string | undefined>
  headers?: Record<string, string>
}

/**
 * Request an access token from the OAuth provider.
 *
 * When an error occurs, only the error data is returned.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
 */
// TODO: waiting for https://github.com/atinux/nuxt-auth-utils/pull/140
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function requestAccessToken(url: string, options: RequestAccessTokenOptions): Promise<any> {
  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    ...options.headers,
  }

  // Encode the body as a URLSearchParams if the content type is 'application/x-www-form-urlencoded'.
  const body = headers['Content-Type'] === 'application/x-www-form-urlencoded'
    ? new URLSearchParams(options.body as unknown as Record<string, string> || options.params || {},
    ).toString()
    : options.body

  return $fetch(url, {
    method: 'POST',
    headers,
    body,
  }).catch((error) => {
    /**
     * For a better error handling, only unauthorized errors are intercepted, and other errors are re-thrown.
     */
    if (error instanceof FetchError && error.status === 401) {
      return error.data
    }
    throw error
  })
}

/**
 * Handle OAuth access token error response
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
 */
// TODO: waiting for https://github.com/atinux/nuxt-auth-utils/pull/140
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function handleAccessTokenErrorResponse(event: H3Event, oauthProvider: OAuthProvider, oauthError: any, onError?: OnError) {
  const message = `${upperFirst(oauthProvider)} login failed: ${oauthError.error_description || oauthError.error || 'Unknown error'}`

  const error = createError({
    statusCode: 401,
    message,
    data: oauthError,
  })

  if (!onError) throw error
  return onError(event, error)
}

export function handleMissingConfiguration(event: H3Event, provider: OAuthProvider, missingKeys: string[], onError?: OnError) {
  const environmentVariables = missingKeys.map(key => `NUXT_OAUTH_${provider.toUpperCase()}_${snakeCase(key).toUpperCase()}`)

  const error = createError({
    statusCode: 500,
    message: `Missing ${environmentVariables.join(' or ')} env ${missingKeys.length > 1 ? 'variables' : 'variable'}.`,
  })

  if (!onError) throw error
  return onError(event, error)
}
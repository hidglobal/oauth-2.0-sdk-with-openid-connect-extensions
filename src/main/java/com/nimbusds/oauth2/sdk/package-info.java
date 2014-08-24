/**
 * Classes for representing, serialising and parsing OAuth 2.0 client requests
 * and server responses.
 *
 * <p>Authorisation endpoint messages:
 *
 * <ul>
 *     <li>{@link com.nimbusds.oauth2.sdk.AuthorizationRequest} The client
 *         requests the end-user's authorisation to access a protected
 *         resource.
 *     <li>{@link com.nimbusds.oauth2.sdk.AuthorizationResponse} The server
 *         grants the authorisation or returns an error:
 *         <ul>
 *             <li>{@link com.nimbusds.oauth2.sdk.AuthorizationSuccessResponse}
 *                 The server responds with an authorisation grant.
 *             <li>{@link com.nimbusds.oauth2.sdk.AuthorizationErrorResponse}
 *                 The server responds with an authorisation error.
 *         </ul>
 *     </li>
 * </ul>
 *
 * <p>Token endpoint messages:
 *
 * <ul>
 *     <li>{@link com.nimbusds.oauth2.sdk.TokenRequest} The client requests an
 *         access token and optional refresh token using a previously issued
 *         authorisation code or other valid grant.
 *     <li>{@link com.nimbusds.oauth2.sdk.TokenResponse} The server responds
 *         with an access token or returns an error:
 *         <ul>
 *             <li>{@link com.nimbusds.oauth2.sdk.AccessTokenResponse} The
 *                 server responds with an access token and optional refresh
 *                 token.
 *             <li>{@link com.nimbusds.oauth2.sdk.TokenErrorResponse} The
 *                 server responds with a token error.
 *         </ul>
 * </ul>
 *
 * <p>Token revocation endpoint messages:
 *
 * <ul>
 *     <li>{@link com.nimbusds.oauth2.sdk.TokenRevocationRequest} The client
 *         request revocation of a previously issued access or refresh
 *         token.
 * </ul>
 * 
 * <p>Protected resource messages:
 * 
 * <ul>
 *     <li>{@link com.nimbusds.oauth2.sdk.ProtectedResourceRequest} The client
 *         makes a request to a protected resource using an OAuth 2.0 access
 *         token.
 */
package com.nimbusds.oauth2.sdk;
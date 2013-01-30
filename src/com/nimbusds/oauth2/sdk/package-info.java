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
 *     <li>{@link com.nimbusds.oauth2.sdk.TokenRequest} The client 
 *         authenticates with the server and requests and access token based on
 *         a previously issued authorisation code or refresh token:
 *         <ul>
 *             <li>{@link com.nimbusds.oauth2.sdk.AccessTokenRequest} The 
 *                 client requests the authorisation code to be exchanged for 
 *                 an access and refresh token.
 *             <li>{@link com.nimbusds.oauth2.sdk.RefreshTokenRequest} The
 *                 client requests a new access token.
 *         </ul>
 *     </li>
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
 * @author Vladimir Dzhuvinov
 * @version $version$ ($version-date$)
 */
package com.nimbusds.oauth2.sdk;
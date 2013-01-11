/**
 * OpenID Connect request, response and error messages.
 *
 * <p>This package implements all required messages for the following OpenID
 * Connect endpoints:
 *
 * <ul>
 *     <li>Authorisation endpoint:
 *         <ul>
 *             <li>{@link com.nimbusds.openid.connect.sdk.messages.AuthorizationRequest}
 *             <li>{@link com.nimbusds.openid.connect.sdk.messages.AuthorizationResponse}
 *             <li>{@link com.nimbusds.openid.connect.sdk.messages.AuthorizationErrorResponse}
 *         </ul>
 *     <li>Token endpoint:
 *         <ul>
 *             <li>{@link com.nimbusds.openid.connect.sdk.messages.AccessTokenRequest}
 *             <li>{@link com.nimbusds.openid.connect.sdk.messages.RefreshTokenRequest}
 *             <li>{@link com.nimbusds.openid.connect.sdk.messages.AccessTokenResponse}
 *             <li>{@link com.nimbusds.openid.connect.sdk.messages.TokenErrorResponse}
 *         </ul>
 *     <li>UserInfo endpoint:
 *         <ul>
 *             <li>{@link com.nimbusds.openid.connect.sdk.messages.UserInfoRequest}
 *             <li>{@link com.nimbusds.openid.connect.sdk.messages.UserInfoResponse}
 *             <li>{@link com.nimbusds.openid.connect.sdk.messages.UserInfoErrorResponse}
 *         </ul>
 *     <li>Client registration endpoint:
 *         <ul>
 *             <li>{@link com.nimbusds.openid.connect.sdk.messages.ClientAssociateRequest}
 *             <li>{@link com.nimbusds.openid.connect.sdk.messages.ClientAssociateResponse}
 *             <li>{@link com.nimbusds.openid.connect.sdk.messages.ClientUpdateRequest}
 *             <li>{@link com.nimbusds.openid.connect.sdk.messages.ClientUpdateResponse}
 *             <li>{@link com.nimbusds.openid.connect.sdk.messages.ClientRotateSecretRequest}
 *             <li>{@link com.nimbusds.openid.connect.sdk.messages.ClientRotateSecretResponse}
 *             <li>{@link com.nimbusds.openid.connect.sdk.messages.ClientRegistrationErrorResponse}
 *         </ul>
 * </ul>
 *
 * <p>Future versions may add support for the optional dynamic client 
 * registration endpoint and session management.
 * 
 * @author Vladimir Dzhuvinov
 * @version $version$ ($version-date$)
 */
package com.nimbusds.openid.connect.sdk.messages;

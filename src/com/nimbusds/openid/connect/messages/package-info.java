/**
 * OpenID Connect request, response and error messages.
 *
 * <p>This package implements all required messages for the following OpenID
 * Connect endpoints:
 *
 * <ul>
 *     <li>Authorisation endpoint:
 *         <ul>
 *             <li>{@link com.nimbusds.openid.connect.messages.AuthorizationRequest}
 *             <li>{@link com.nimbusds.openid.connect.messages.AuthorizationResponse}
 *             <li>{@link com.nimbusds.openid.connect.messages.AuthorizationErrorResponse}
 *         </ul>
 *     <li>Token endpoint:
 *         <ul>
 *             <li>{@link com.nimbusds.openid.connect.messages.AccessTokenRequest}
 *             <li>{@link com.nimbusds.openid.connect.messages.RefreshTokenRequest}
 *             <li>{@link com.nimbusds.openid.connect.messages.AccessTokenResponse}
 *             <li>{@link com.nimbusds.openid.connect.messages.TokenErrorResponse}
 *         </ul>
 *     <li>UserInfo endpoint:
 *         <ul>
 *             <li>{@link com.nimbusds.openid.connect.messages.UserInfoRequest}
 *             <li>{@link com.nimbusds.openid.connect.messages.UserInfoResponse}
 *             <li>{@link com.nimbusds.openid.connect.messages.UserInfoErrorResponse}
 *         </ul>
 * </ul>
 *
 * <p>Future versions may add support for the optional dynamic client 
 * registration endpoint and session management.
 * 
 * @author Vladimir Dzhuvinov
 * @version $version$ ($version-date$)
 */
package com.nimbusds.openid.connect.messages;

/**
 * Implementations of OAuth 2.0 client authentication methods at the Token 
 * endpoint.
 *
 * <p>The following authentication methods are supported:
 *
 * <ul>
 *     <li>{@link com.nimbusds.oauth2.sdk.auth.ClientSecretBasic} (the default)
 *     <li>{@link com.nimbusds.oauth2.sdk.auth.ClientSecretPost}
 *     <li>{@link com.nimbusds.oauth2.sdk.auth.ClientSecretJWT}
 *     <li>{@link com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT}
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-18)
 */
package com.nimbusds.oauth2.sdk.auth;
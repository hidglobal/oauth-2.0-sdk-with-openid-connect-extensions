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
 */
package com.nimbusds.oauth2.sdk.auth;
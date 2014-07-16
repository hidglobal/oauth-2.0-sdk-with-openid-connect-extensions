package com.nimbusds.oauth2.sdk.auth;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Client authentication method at the Token endpoint.
 *
 * <p>Constants are provided for four client authentication methods:
 *
 * <ul>
 *     <li>{@link #CLIENT_SECRET_BASIC} (default)
 *     <li>{@link #CLIENT_SECRET_POST}
 *     <li>{@link #CLIENT_SECRET_JWT}
 *     <li>{@link #PRIVATE_KEY_JWT}
 *     <li>{@link #NONE}
 * </ul>
 *
 * <p>Use the constructor to define a custom client authentication method.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 2.3.
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol
 *         (draft-ietf-oauth-dyn-reg-18), section 2.
 * </ul>
 */
@Immutable
public final class ClientAuthenticationMethod extends Identifier {


	/**
	 * Clients that have received a client secret from the authorisation 
	 * server authenticate with the authorisation server in accordance with
	 * section 3.2.1 of OAuth 2.0 using HTTP Basic authentication. This is 
	 * the default if no method has been registered for the client.
	 */
	public static final ClientAuthenticationMethod CLIENT_SECRET_BASIC = 
		new ClientAuthenticationMethod("client_secret_basic");


	/**
	 * Clients that have received a client secret from the authorisation 
	 * server authenticate with the authorisation server in accordance with
	 * section 3.2.1 of OAuth 2.0 by including the client credentials in 
	 * the request body.
	 */
	public static final ClientAuthenticationMethod CLIENT_SECRET_POST =
		new ClientAuthenticationMethod("client_secret_post");


	/**
	 * Clients that have received a client secret from the authorisation 
	 * server, create a JWT using an HMAC SHA algorithm, such as HMAC 
	 * SHA-256. The HMAC (Hash-based Message Authentication Code) is
	 * calculated using the value of client secret as the shared key. The 
	 * client authenticates in accordance with section 2.2 of (JWT) Bearer
	 * Token Profiles and OAuth 2.0 Assertion Profile. 
	 */
	public static final ClientAuthenticationMethod CLIENT_SECRET_JWT =
		new ClientAuthenticationMethod("client_secret_jwt");


	/**
	 * Clients that have registered a public key sign a JWT using the RSA 
	 * algorithm if a RSA key was registered or the ECDSA algorithm if an 
	 * Elliptic Curve key was registered (see JWA for the algorithm 
	 * identifiers). The client authenticates in accordance with section 
	 * 2.2 of (JWT) Bearer Token Profiles and OAuth 2.0 Assertion Profile.
	 */
	public static final ClientAuthenticationMethod PRIVATE_KEY_JWT =
		new ClientAuthenticationMethod("private_key_jwt");


	/**
	 * The client is a public client as defined in OAuth 2.0 and does not
	 * have a client secret.
	 */
	public static final ClientAuthenticationMethod NONE =
		new ClientAuthenticationMethod("none");


	/**
	 * Gets the default client authentication method.
	 *
	 * @return {@link #CLIENT_SECRET_BASIC}
	 */
	public static ClientAuthenticationMethod getDefault() {

		return CLIENT_SECRET_BASIC;
	}


	/**
	 * Creates a new client authentication method with the specified value.
	 *
	 * @param value The authentication method value. Must not be 
	 *              {@code null} or empty string.
	 */
	public ClientAuthenticationMethod(final String value) {

		super(value);
	}


	/**
	 * Parses a client authentication method from the specified value.
	 *
	 * @param value The authentication method value. Must not be
	 *              {@code null} or empty string.
	 *
	 * @return The client authentication method.
	 */
	public static ClientAuthenticationMethod parse(final String value) {

		if (value.equals(CLIENT_SECRET_BASIC.getValue())) {
			return CLIENT_SECRET_BASIC;
		} else if (value.equals(CLIENT_SECRET_POST.getValue())) {
			return CLIENT_SECRET_POST;
		} else if (value.equals(CLIENT_SECRET_JWT.getValue())) {
			return CLIENT_SECRET_JWT;
		} else if (value.equals(PRIVATE_KEY_JWT.getValue())) {
			return PRIVATE_KEY_JWT;
		} else if (value.equals(NONE.getValue())) {
			return NONE;
		} else {
			return new ClientAuthenticationMethod(value);
		}
	}


	@Override
	public boolean equals(final Object object) {
	
		return object instanceof ClientAuthenticationMethod &&
		       this.toString().equals(object.toString());
	}
}
package com.nimbusds.openid.connect.sdk.claims;


/**
 * Enumeration of the available claims transports.
 */
public enum ClaimsTransport {


	/**
	 * The claims are returned at the UserInfo endpoint.
	 */
	USERINFO,


	/**
	 * The claims are returned with the ID token.
	 */
	ID_TOKEN;


	/**
	 * Returns the default claims transport.
	 *
	 * @return The default claims transport.
	 */
	public static ClaimsTransport getDefault() {

		return USERINFO;
	}
}

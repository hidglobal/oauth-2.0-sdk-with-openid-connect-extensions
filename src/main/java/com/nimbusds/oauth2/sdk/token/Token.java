package com.nimbusds.oauth2.sdk.token;


import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * The base abstract class for access and refresh tokens.
 * 
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 1.4 and 1.5.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
public abstract class Token extends Identifier {


	/**
	 * Creates a new token with the specified value.
	 *
	 * @param value The token value. Must not be {@code null} or empty 
	 *              string.
	 */
	protected Token(final String value) {

		super(value);
	}


	/**
	 * Creates a new token with a randomly generated value of the specified 
	 * byte length, Base64URL-encoded.
	 *
	 * @param byteLength The byte length of the value to generate. Must be
	 *                   greater than one.
	 */
	protected Token(final int byteLength) {
	
		super(byteLength);
	}
	
	
	/**
	 * Creates a new token with a randomly generated 256-bit (32-byte) 
	 * value, Base64URL-encoded.
	 */
	protected Token() {
	
		super();
	}


	/**
	 * Returns the token parameters as a JSON object, as required for the
	 * composition of an access token response. See OAuth 2.0 (RFC 6749), 
	 * section 5.1.
	 *
	 * <p>Note that JSONObject implements {@code Map<String,Object>}.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * {
	 *   "access_token"      : "2YotnFZFEjr1zCsicMWpAA",
	 *   "token_type"        : "example",
	 *   "expires_in"        : 3600,
	 *   "example_parameter" : "example_value"
	 * }
	 * </pre>
	 *
	 * @return The token parameters as a JSON object.
	 */
	public abstract JSONObject toJSONObject();
}

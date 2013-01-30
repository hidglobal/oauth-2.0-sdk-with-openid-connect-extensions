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
 * @version $version$ (2014-01-18)
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
	 * length. The value will be made up of mixed-case alphanumeric ASCII 
	 * characters.
	 *
	 * @param length The number of characters. Must be a positive integer.
	 */
	protected Token(final int length) {
	
		super(length);
	}
	
	
	/**
	 * Creates a new token with a randomly generated value. The value will 
	 * be made up of 32 mixed-case alphanumeric ASCII characters.
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

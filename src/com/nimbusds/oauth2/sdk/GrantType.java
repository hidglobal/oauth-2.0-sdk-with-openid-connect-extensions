package com.nimbusds.openid.connect.sdk.messages;


import com.nimbusds.openid.connect.sdk.ParseException;


/**
 * Enumeration of the OAuth 2.0 grant types used by OpenID Connect.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749).
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-09)
 */
public enum GrantType {

	
	/**
	 * Authorisation code.
	 */
	AUTHORIZATION_CODE,
	
	
	/**
	 * Refresh token.
	 */
	REFRESH_TOKEN;
	
	
	/**
	 * Returns the string identifier of this grant type.
	 *
	 * @return The string identifier.
	 */
	@Override
	public String toString() {
	
		return super.toString().toLowerCase();
	}
	
	
	/**
	 * Parses a grant type.
	 *
	 * @param s The string identifier of a grant type. Must not be 
	 *          {@code null}.
	 *
	 * @return The grant type.
	 *
	 * @throws ParseException If the string doesn't match a supported grant 
	 *                        type.
	 */
	public static GrantType parse(final String s)
		throws ParseException {
	
		if (s == null || s.trim().isEmpty())
			throw new ParseException("Null or empty grant type string");
		
		if (s.equals("authorization_code"))
			return AUTHORIZATION_CODE;
			
		else if (s.equals("refresh_token"))
			return REFRESH_TOKEN;
			
		else
			throw new ParseException("Unknown grant type: " + s);
	}
}

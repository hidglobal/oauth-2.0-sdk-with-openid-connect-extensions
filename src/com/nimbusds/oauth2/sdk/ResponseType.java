package com.nimbusds.openid.connect.sdk.messages;


import com.nimbusds.openid.connect.sdk.ParseException;


/**
 * Enumeration of the individual registered OpenID Connect response types.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Standard 1.0, section 2.3.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-09)
 */
public enum ResponseType {

	
	/**
	 * Authorization Code.
	 */
	CODE,
	
	
	/**
	 * ID Token.
	 */
	ID_TOKEN,
	
	
	/**
	 * Access Token.
	 */
	TOKEN;
	
	
	/**
	 * Returns the string identifier of this response type.
	 *
	 * @return The string identifier.
	 */
	@Override
	public String toString() {
	
		return super.toString().toLowerCase();
	}
	
	
	/**
	 * Parses an individual response type.
	 *
	 * @param s The string to parse.
	 *
	 * @return The individual response type.
	 *
	 * @throws ParseException If the parsed string doesn't match an 
	 *                        individual response type.
	 */
	public static ResponseType parse(final String s)
		throws ParseException {
	
		if (s == null || s.trim().isEmpty())
			throw new ParseException("Null or empty response type string");
		
		if (s.equals("code"))
			return CODE;
			
		else if (s.equals("id_token"))
			return ID_TOKEN;
			
		else if (s.equals("token"))
			return TOKEN;
		
		else
			throw new ParseException("Unknown response type: " + s);
	}
}

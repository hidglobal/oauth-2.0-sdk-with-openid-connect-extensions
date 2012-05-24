package com.nimbusds.openid.connect.messages;


import com.nimbusds.openid.connect.ParseException;


/**
 * Enumeration of the individual registered OpenID Connect response types.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Standard 1.0, section 2.2.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-24)
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
	 * Returns the canonical name of this response type.
	 *
	 * @return The canonical name of this response type.
	 */
	public String toString() {
	
		return super.toString().toLowerCase();
	}
	
	
	/**
	 * Parses an individual response type.
	 *
	 * @param s The string to parse.
	 *
	 * @return The parsed individual response type.
	 *
	 * @throws ParseException If the parsed string doesn't match an 
	 *                        individual response type.
	 */
	public static ResponseType parse(final String s)
		throws ParseException {
	
		if (s == null || s.trim().isEmpty())
			throw new ParseException("Null or empty string");
		
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

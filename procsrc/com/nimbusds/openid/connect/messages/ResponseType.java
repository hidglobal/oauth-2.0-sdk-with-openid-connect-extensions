package com.nimbusds.openid.connect.messages;


import com.nimbusds.openid.connect.ParseException;


/**
 * Enumeration of the individual registered OpenID Connect response types.
 *
 * @author Vladimir Dzhuvinov
 * @version 0.9 (2012-04-22)
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
			throw new ParseException("Couldn't parse response type: Null or empty value");
		
		if (s.equals("code"))
			return CODE;
			
		else if (s.equals("id_token"))
			return ID_TOKEN;
			
		else if (s.equals("token"))
			return TOKEN;
		
		else
			throw new ParseException("Couldn't parse response type: Unexpected response type: " + s);
	}
}

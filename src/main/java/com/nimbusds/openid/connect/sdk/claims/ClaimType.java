package com.nimbusds.openid.connect.sdk.claims;


import com.nimbusds.oauth2.sdk.ParseException;


/**
 * Enumeration of the claim types. This class is immutable.
 * 
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.7.
 *     <li>OpenID Connect Discovery, section 3.
 * </ul>
 */
public enum ClaimType {
	
	/**
	 * Claims that are directly asserted by the OpenID Connect provider. 
	 */
	NORMAL,
		
	
	/**
	 * Claims that are asserted by a claims provider other than the 
	 * OpenID Connect Provider but are returned by OpenID Connect provider. 
	 */
	AGGREGATED,
		
	
	/**
	 * Claims that are asserted by a claims provider other than the OpenID
	 * Connect provider but are returned as references by the OpenID 
	 * Connect provider. 
	 */
	DISTRIBUTED;

	
	/**
	 * Returns the string identifier of this claim type.
	 *
	 * @return The string identifier.
	 */
	@Override
	public String toString() {
		
		return super.toString().toLowerCase();
	}
	
	
	/**
	 * Parses a claim type.
	 * 
	 * @param s The string to parse. Must not be {@code null}.
	 * 
	 * @return The claim type.
	 */
	public static ClaimType parse(final String s)
		throws ParseException {
		
		if (s.equals("normal"))
			return NORMAL;
		
		if (s.equals("aggregated"))
			return AGGREGATED;
		
		if (s.equals("distributed"))
			return DISTRIBUTED;
		
		throw new ParseException("Unknow claim type: " + s);
	}
}

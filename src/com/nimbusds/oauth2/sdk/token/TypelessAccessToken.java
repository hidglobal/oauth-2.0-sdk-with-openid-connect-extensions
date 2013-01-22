package com.nimbusds.oauth2.sdk.token;


import net.minidev.json.JSONObject;


/**
 * Typeless access token, cannot be serialized. Intended to represent parsed
 * access tokens which type cannot be inferred.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 1.4 and 5.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-22)
 */
public class TypelessAccessToken extends AccessToken {

	
	/**
	 * Creates a new minimal type;ess access token with the specified 
	 * value. The optional lifetime and scope are left undefined.
	 *
	 * @param value The access token value. Must not be {@code null} or
	 *              empty string.
	 */
	public TypelessAccessToken(final String value) {
	
		super(AccessTokenType.UNKNOWN, value);
	}


	/**
	 * Operation not supported.
	 * 
	 * @throws UnsupportedOperationException Serialisation is not 
	 *                                       supported.
	 */
	@Override
	public JSONObject toJSONObject() {

		throw new UnsupportedOperationException("Serialization not supported");
	}
	
	
	/**
	 * Operation not supported.
	 * 
	 * @throws UnsupportedOperationException Serialisation is not 
	 *                                       supported.
	 */
	@Override
	public String toAuthorizationHeader() {

		throw new UnsupportedOperationException("Serialization not supported");
	}
	
	
	@Override
	public boolean equals(final Object object) {
	
		return object != null && 
		       object instanceof AccessToken && 
		       this.toString().equals(object.toString());
	}
}

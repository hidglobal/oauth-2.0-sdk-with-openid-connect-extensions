package com.nimbusds.oauth2.sdk.token;


import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.ParseException;


/**
 * Refresh token. This class is immutable.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 1.5.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
@Immutable
public final class RefreshToken
	extends Token
	implements Comparable<RefreshToken> {


	/**
	 * Creates a new refresh token with a randomly generated 256-bit 
	 * (32-byte) value, Base64URL-encoded.
	 */
	public RefreshToken() {
	
		this(32);
	}	


	/**
	 * Creates a new refresh token with a randomly generated value of the 
	 * specified length, Base64URL-encoded.
	 *
	 * @param byteLength The byte length of the value to generate. Must be
	 *                   greater than one.
	 */
	public RefreshToken(final int byteLength) {
	
		super(byteLength);
	}


	/**
	 * Creates a new refresh token with the specified value.
	 *
	 * @param value The refresh token value. Must not be {@code null} or 
	 *              empty string.
	 */
	public RefreshToken(final String value) {
	
		super(value);
	}


	@Override
	public JSONObject toJSONObject() {

		JSONObject o = new JSONObject();

		o.put("refresh_token", value());
		
		return o;
	}


	/**
	 * Parses a refresh token from a JSON object access token response.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The refresh token, {@code null} if not found.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a
	 *                        refresh token.
	 */
	public static RefreshToken parse(final JSONObject jsonObject)
		throws ParseException {

		// Parse value
		if (! jsonObject.containsKey("refresh_token"))
			return null;

		String value = JSONObjectUtils.getString(jsonObject, "refresh_token");

		return new RefreshToken(value);
	}


	@Override
	public boolean equals(final Object object) {
	
		return object != null && 
		       object instanceof RefreshToken && 
		       this.toString().equals(object.toString());
	}


	@Override
	public int compareTo(RefreshToken other) {

		return value().compareTo(other.value());
	}
}

package com.nimbusds.oauth2.sdk.token;


import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;


/**
 * The base abstract class for access tokens. Concrete extending classes should
 * be immutable.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 1.4 and 5.1.
 * </ul>
 */
public abstract class AccessToken extends Token {

	
	/**
	 * The access token type.
	 */
	private final AccessTokenType type;
	
	
	/**
	 * Optional lifetime, in seconds.
	 */
	private final long lifetime;
	
	
	/**
	 * Optional scope.
	 */
	private final Scope scope;


	/**
	 * Creates a new minimal access token with a randomly generated 256-bit 
	 * (32-byte) value, Base64URL-encoded. The optional lifetime and scope 
	 * are left undefined.
	 *
	 * @param type The access token type. Must not be {@code null}.
	 */
	public AccessToken(final AccessTokenType type) {
	
		this(type, 32);
	}


	/**
	 * Creates a new minimal access token with a randomly generated value 
	 * of the specified byte length, Base64URL-encoded. The optional 
	 * lifetime and scope are left undefined.
	 *
	 * @param type       The access token type. Must not be {@code null}.
	 * @param byteLength The byte length of the value to generate. Must be
	 *                   greater than one.
	 */
	public AccessToken(final AccessTokenType type, final int byteLength) {
	
		this(type, byteLength, 0l, null);
	}


	/**
	 * Creates a new access token with a randomly generated 256-bit 
	 * (32-byte) value, Base64URL-encoded.
	 *
	 * @param type     The access token type. Must not be {@code null}.
	 * @param lifetime The lifetime in seconds, 0 if not specified.
	 * @param scope    The scope, {@code null} if not specified.
	 */
	public AccessToken(final AccessTokenType type,
		           final long lifetime, 
		           final Scope scope) {
	
		this(type, 32, lifetime, scope);
	}


	/**
	 * Creates a new access token with a randomly generated value 
	 * of the specified byte length, Base64URL-encoded, and optional 
	 * lifetime and scope.
	 *
	 * @param type       The access token type. Must not be {@code null}.
	 * @param byteLength The byte length of the value to generate. Must be
	 *                   greater than one.
	 * @param lifetime   The lifetime in seconds, 0 if not specified.
	 * @param scope      The scope, {@code null} if not specified.
	 */
	public AccessToken(final AccessTokenType type, 
		           final int byteLength, 
		           final long lifetime, 
		           final Scope scope) {
	
		super(byteLength);

		if (type == null)
			throw new IllegalArgumentException("The access token type must not be null");

		this.type = type;

		this.lifetime = lifetime;
		this.scope = scope;
	}
	
	
	/**
	 * Creates a new minimal access token with the specified value. The 
	 * optional lifetime and scope are left undefined.
	 *
	 * @param type  The access token type. Must not be {@code null}.
	 * @param value The access token value. Must not be {@code null} or
	 *              empty string.
	 */
	public AccessToken(final AccessTokenType type, final String value) {
	
		this(type, value, 0l, null);
	}
	
	
	/**
	 * Creates a new access token with the specified value and optional 
	 * lifetime and scope.
	 *
	 * @param type     The access token type. Must not be {@code null}.
	 * @param value    The access token value. Must not be {@code null} or
	 *                 empty string.
	 * @param lifetime The lifetime in seconds, 0 if not specified.
	 * @param scope    The scope, {@code null} if not specified.
	 */
	public AccessToken(final AccessTokenType type, 
		           final String value, 
		           final long lifetime, 
		           final Scope scope) {
	
		super(value);

		if (type == null)
			throw new IllegalArgumentException("The access token type must not be null");

		this.type = type;

		this.lifetime = lifetime;
		this.scope = scope;
	}


	/**
	 * Returns the access token type.
	 *
	 * @return The access token type.
	 */
	public AccessTokenType getType() {

		return type;
	}

	
	/**
	 * Returns the lifetime of this access token.
	 *
	 * @return The lifetime in seconds, 0 if not specified.
	 */
	public long getLifetime() {
	
		return lifetime;
	}
	
	
	/**
	 * Returns the scope of this access token.
	 *
	 * @return The scope, {@code null} if not specified.
	 */
	public Scope getScope() {
	
		return scope;
	}


	@Override
	public JSONObject toJSONObject() {

		JSONObject o = new JSONObject();

		o.put("access_token", getValue());
		o.put("token_type", type.toString());
		
		if (getLifetime() > 0)
			o.put("expires_in", lifetime);

		if (getScope() != null)
			o.put("scope", scope.toString());
		
		return o;
	}


	@Override
	public String toJSONString() {

		return toJSONObject().toString();
	}
	
	
	/**
	 * Returns the {@code Authorization} HTTP request header value for this
	 * access token.
	 *
	 * @return The {@code Authorization} header value.
	 */
	public abstract String toAuthorizationHeader();


	/**
	 * Parses an access token from a JSON object access token response.
	 * Only bearer access tokens are supported.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The access token.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an
	 *                        access token.
	 */
	public static AccessToken parse(final JSONObject jsonObject)
		throws ParseException {

		return BearerAccessToken.parse(jsonObject);
	}
	
	
	/**
	 * Parses an {@code Authorization} HTTP request header value for an 
	 * access token. Only bearer access token are supported.
	 *
	 * @param header The {@code Authorization} header value to parse. Must 
	 *               not be {@code null}.
	 *
	 * @return The access token.
	 *
	 * @throws ParseException If the {@code Authorization} header value 
	 *                        couldn't be parsed to an access token.
	 */
	public static AccessToken parse(final String header)
		throws ParseException {
	
		return BearerAccessToken.parse(header);
	}
}

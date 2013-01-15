package com.nimbusds.openid.connect.sdk.messages;


import net.jcip.annotations.Immutable;

import com.nimbusds.openid.connect.sdk.ParseException;


/**
 * OAuth 2.0 access token. Supports only {@link #TYPE bearer type} tokens. This
 * class is immutable.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 1.4.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-12)
 */
@Immutable
public final class AccessToken extends Token {

	
	/**
	 * The token type, set to "Bearer" (OAuth.Bearer).
	 */
	public static final String TYPE = "Bearer";
	
	
	/**
	 * Optional lifetime, in seconds.
	 */
	private final long lifetime;
	
	
	/**
	 * Optional scope.
	 */
	private final Scope scope;


	/**
	 * Creates a new minimal OAuth 2.0 access token with a randomly 
	 * generated value. The value will be made up of 32 mixed-case 
	 * alphanumeric ASCII characters. The optional lifetime and scope are 
	 * left undefined.
	 */
	public AccessToken() {
	
		this(32);
	}	


	/**
	 * Creates a new minimal OAuth 2.0 access token with a randomly 
	 * generated value of the specified length. The value will be made up 
	 * of mixed-case alphanumeric ASCII characters. The optional lifetime 
	 * and scope are left undefined.
	 *
	 * @param length The number of characters. Must be a positive integer.
	 */
	public AccessToken(final int length) {
	
		this(length, 0l, null);
	}


	/**
	 * Creates a new OAuth 2.0 access token with a randomly generated value
	 * and the specified optional lifetime and scope. The value will be 
	 * made up of 32 mixed-case alphanumeric ASCII characters.
	 *
	 * @param lifetime The lifetime in seconds, 0 if not specified.
	 * @param scope    The scope, {@code null} if not specified.
	 */
	public AccessToken(final long lifetime, final Scope scope) {
	
		this(32, lifetime, scope);
	}


	/**
	 * Creates a new OAuth 2.0 access token with a randomly generated value
	 * of the specified length and optional lifetime and scope. The value 
	 * will be made up of mixed-case alphanumeric ASCII characters.
	 *
	 * @param length   The number of characters. Must be a positive 
	 *                 integer.
	 * @param lifetime The lifetime in seconds, 0 if not specified.
	 * @param scope    The scope, {@code null} if not specified.
	 */
	public AccessToken(final int length, final long lifetime, final Scope scope) {
	
		super(length);
		this.lifetime = lifetime;
		this.scope = scope;
	}
	
	
	/**
	 * Creates a new minimal OAuth 2.0 access token with the specified
	 * value. The optional lifetime and scope are left undefined.
	 *
	 * @param value The access token value. Must not be {@code null} or
	 *              empty string.
	 */
	public AccessToken(final String value) {
	
		this(value, 0l, null);
	}
	
	
	/**
	 * Creates a new OAuth 2.0 access token with the specified value and
	 * optional lifetime and scope.
	 *
	 * @param value    The access token value. Must not be {@code null} or
	 *                 empty string.
	 * @param lifetime The lifetime in seconds, 0 if not specified.
	 * @param scope    The scope, {@code null} if not specified.
	 */
	public AccessToken(final String value, final long lifetime, final Scope scope) {
	
		super(value);
		this.lifetime = lifetime;
		this.scope = scope;
	}

	
	/**
	 * Gets the lifetime of this access token.
	 *
	 * @return The lifetime in seconds, 0 if not specified.
	 */
	public long getLifetime() {
	
		return lifetime;
	}
	
	
	/**
	 * Gets the scope of this access token.
	 *
	 * @return The scope, {@code null} if not specified.
	 */
	public Scope getScope() {
	
		return scope;
	}
	
	
	/**
	 * Returns the HTTP Authorization header value for this access token.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * Authorization: Bearer eyJhbGciOiJIUzI1NiJ9
	 * </pre>
	 *
	 * @return The HTTP Authorization header value for this access token.
	 */
	public String toAuthorizationHeader(){
	
		return "Bearer " + getValue();
	}
	
	
	/**
	 * Overrides {@code Object.equals()}.
	 *
	 * @param object The object to compare to.
	 *
	 * @return {@code true} if the objects have the same value, otherwise
	 *         {@code false}.
	 */
	@Override
	public boolean equals(final Object object) {
	
		return object instanceof AccessToken && this.toString().equals(object.toString());
	}
	
	
	/**
	 * Parses an HTTP Authorization header for an access token of 
	 * {@link #TYPE type Bearer}.
	 *
	 * @param header The HTTP Authorization header value to parse. Must not
	 *               be {@code null}.
	 *
	 * @return The access token.
	 *
	 * @throws ParseException If the HTTP Authorization header value 
	 *                        couldn't be parsed to a valid access token of
	 *                        type Bearer.
	 */
	public static AccessToken parse(final String header)
		throws ParseException {
	
		String[] parts = header.split("\\s", 2);
	
		if (parts.length != 2)
			throw new ParseException("Invalid HTTP Authorization header value");
		
		if (! parts[0].equals("Bearer"))
			throw new ParseException("Token type must be \"Bearer\"");
		
		try {
			return new AccessToken(parts[1]);
			
		} catch (IllegalArgumentException e) {
		
			throw new ParseException(e.getMessage());
		}
	}
}

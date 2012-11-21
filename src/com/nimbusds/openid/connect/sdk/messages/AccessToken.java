package com.nimbusds.openid.connect.sdk.messages;


import net.jcip.annotations.Immutable;

import org.apache.commons.lang3.RandomStringUtils;

import com.nimbusds.openid.connect.sdk.ParseException;

import com.nimbusds.openid.connect.sdk.util.StringUtils;


/**
 * OAuth 2.0 access token. Supports only {@link #TYPE bearer type} tokens. This
 * class is immutable.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 1.4 and section 4.2.2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-11-21)
 */
@Immutable
public final class AccessToken {

	
	/**
	 * The token type, set to "Bearer" (OAuth.Bearer).
	 */
	public static final String TYPE = "Bearer";
	
	
	/**
	 * The access token value.
	 */
	private final String value;
	
	
	/**
	 * Optional expiration, in seconds.
	 */
	private final long exp;
	
	
	/**
	 * Optional scope.
	 */
	private final Scope scope;
	
	
	/**
	 * Creates a new minimal OAuth 2.0 access token. The optional expiration
	 * and scope are left undefined.
	 *
	 * @param value The access token value. Must not be {@code null} or
	 *              empty string.
	 *
	 * @throws IllegalArgumentException If the access token value is
	 *                                  {@code null} or empty string.
	 */
	public AccessToken(final String value) {
	
		this(value, 0l, null);
	}
	
	
	/**
	 * Creates a new OAuth 2.0 access token.
	 *
	 * @param value The access token value. Must not be {@code null} or
	 *              empty string.
	 * @param exp   The expiration in seconds, 0 if not specified.
	 * @param scope The scope, {@code null} if not specified.
	 */
	public AccessToken(final String value, final long exp, final Scope scope) {
	
		if (StringUtils.isUndefined(value))
			throw new IllegalArgumentException("The access token value must not be null or empty string");
			
		this.value = value;
		
		this.exp = exp;
		
		this.scope = scope;
	}
	
	
	/**
	 * Gets the value of this access token.
	 *
	 * @return The value.
	 */
	public String getValue() {
	
		return value;
	}
	
	
	/**
	 * Gets the optional expiration.
	 *
	 * @return The expiration in seconds, 0 if not specified.
	 */
	public long getExpiration() {
	
		return exp;
	}
	
	
	/**
	 * Gets the optional scope.
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
	
		return "Bearer " + value;
	}


	/**
	 * Gets the string representation of this access token.
	 *
	 * <p> See {@link #getValue}.
	 *
	 * @return The access token value.
	 */
	@Override
	public String toString() {
	
		return value;
	}


	/**
	 * Overrides {@code Object.hashCode()}.
	 *
	 * @return The object hash code.
	 */
	@Override
	public int hashCode() {
	
		return value.hashCode();
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


	/**
	 * Generates a random OAuth 2.0 access token with the specified number 
	 * of alphanumeric characters.
	 *
	 * @param count The number of characters.
	 * @param exp   The expiration in seconds, 0 if not specified.
	 * @param scope The scope, {@code null} if not specified.
	 */
	public static AccessToken generate(final int count, final long exp, final Scope scope) {

		return new AccessToken(RandomStringUtils.randomAlphanumeric(count), exp, scope);
	}


	/**
	 * Generates a random minimal OAuth 2.0 access token with the specified 
	 * number of alphanumeric characters.
	 *
	 * @param count The number of characters.
	 *
	 * @return A new random access token.
	 */
	public static AccessToken generate(final int count) {
	
		return generate(count, 0l, null);
	}
	
	
	/**
	 * Generates a random minimal OAuth 2.0 access token code with 8 
	 * alphanumeric characters.
	 *
	 * @return A new random access token.
	 */
	public static AccessToken generate() {
	
		return generate(8);
	}
}

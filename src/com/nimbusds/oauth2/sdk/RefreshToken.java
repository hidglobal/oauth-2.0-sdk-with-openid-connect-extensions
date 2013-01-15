package com.nimbusds.oauth2.sdk;


import net.jcip.annotations.Immutable;


/**
 * OAuth 2.0 refresh token. This class is immutable.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 1.5.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-15)
 */
@Immutable
public final class RefreshToken extends Token {


	/**
	 * Creates a new OAuth 2.0 refresh token with a randomly generated 
	 * value. The value will be made up of 32 mixed-case alphanumeric ASCII
	 * characters.
	 */
	public RefreshToken() {
	
		this(32);
	}	


	/**
	 * Creates a new OAuth 2.0 refresh token with a randomly generated 
	 * value of the specified length. The value will be made up of 
	 * mixed-case alphanumeric ASCII characters.
	 *
	 * @param length The number of characters. Must be a positive integer.
	 */
	public RefreshToken(final int length) {
	
		super(length);
	}


	/**
	 * Creates a new OAuth 2.0 refresh token with the specified value.
	 *
	 * @param value The refresh token value. Must not be {@code null} or 
	 *              empty string.
	 */
	public RefreshToken(final String value) {
	
		super(value);
	}


	@Override
	public boolean equals(final Object object) {
	
		return object != null && 
		       object instanceof RefreshToken && 
		       this.toString().equals(object.toString());
	}
}

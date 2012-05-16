package com.nimbusds.openid.connect.messages;


/**
 * OAuth 2.0 access token. Supports only {@link #TYPE bearer type} tokens.
 *
 * <p>See draft-ietf-oauth-v2-26, section 1.4 and section 4.2.2.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-13)
 */
public class AccessToken {

	
	/**
	 * The token type, set to "Bearer" (OAuth.Bearer).
	 */
	public static final String TYPE = "Bearer";
	
	
	/**
	 * The access token value.
	 */
	private String value;
	
	
	/**
	 * Optional expiration, in seconds.
	 */
	private long exp = -1l;
	
	
	/**
	 * Optional scope.
	 */
	private Scope scope = null;
	
	
	/**
	 * Creates a new minimal OAuth 2.0 access token.
	 *
	 * @param value The access token value. Must not be {@code null} or
	 *              empty string.
	 *
	 * @throws IllegalArgumentException If the access token value is
	 *                                  {@code null} or empty string.
	 */
	public AccessToken(final String value) {
	
		if (value == null || value.trim().isEmpty())
			throw new IllegalArgumentException("The access token value must not be null or empty string");
			
		this.value = value;
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
	 * @return The expiration in seconds, -1 if not specified.
	 */
	public long getExpiration() {
	
		return exp;
	}
	
	
	/**
	 * Sets the optional expiration time.
	 *
	 * @param exp The expiration in seconds, -1 if not specified.
	 */
	public void setExpiration(final long exp) {
	
		this.exp = exp;
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
	 * Sets the optional scope.
	 *
	 * @param scope The scope, {@code null} if not specified.
	 */
	public void setScope(final Scope scope) {
	
		this.scope = scope;
	}
}

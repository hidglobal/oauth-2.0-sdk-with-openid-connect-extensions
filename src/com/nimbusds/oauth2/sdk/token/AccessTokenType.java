package com.nimbusds.oauth2.sdk.token;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Access token type. This class is immutable.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-19)
 */
@Immutable
public final class AccessTokenType extends Identifier {

	
	/**
	 * Bearer, see OAuth 2.0 Bearer Token Usage (RFC 6750).
	 */
	public static final AccessTokenType BEARER = new AccessTokenType("Bearer");
	
	
	/**
	 * MAC, see OAuth 2.0 Message Authentication Code (MAC) Tokens 
	 * (draft-ietf-oauth-v2-http-mac-02).
	 */
	public static final AccessTokenType MAC = new AccessTokenType("mac");


	/**
	 * Creates a new access token type with the specified value.
	 *
	 * @param value The access token type value. Must not be {@code null} 
	 *              or empty string.
	 */
	public AccessTokenType(final String value) {

		super(value);
	}


	@Override
	public boolean equals(final Object object) {
	
		return object != null && 
		       object instanceof AccessTokenType && 
		       this.toString().equals(object.toString());
	}
}

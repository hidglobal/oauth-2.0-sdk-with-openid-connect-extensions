package com.nimbusds.openid.connect.sdk.claims;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Access token hash ({@code at_hash}). This class is immutable.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.1.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-22)
 */
@Immutable
public final class AccessTokenHash extends Identifier {


	/**
	 * Creates a new access token hash with the specified value.
	 *
	 * @param value The access token hash value. Must not be {@code null}.
	 */
	public AccessTokenHash(final String value) {
	
		super(value);
	}


	@Override
	public boolean equals(final Object object) {
	
		return object != null && 
		       object instanceof AccessTokenHash && 
		       this.toString().equals(object.toString());
	}
}

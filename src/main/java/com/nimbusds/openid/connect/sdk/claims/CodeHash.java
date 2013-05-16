package com.nimbusds.openid.connect.sdk.claims;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Authorisation code hash ({@code c_hash}). This class is immutable.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.1.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
@Immutable
public final class CodeHash extends Identifier {


	/**
	 * Creates a new authorisation code hash with the specified value.
	 *
	 * @param value The authorisation code hash value. Must not be 
	 *              {@code null}.
	 */
	public CodeHash(final String value) {
	
		super(value);
	}


	@Override
	public boolean equals(final Object object) {
	
		return object != null && 
		       object instanceof CodeHash && 
		       this.toString().equals(object.toString());
	}
}

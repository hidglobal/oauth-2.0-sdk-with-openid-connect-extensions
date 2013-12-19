package com.nimbusds.openid.connect.sdk.claims;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Authentication Method Reference ({@code amr}). It identifies the method
 * used in authentication.
 *
 * <p>The AMR is represented by a string or an URL string.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 2.
 * </ul>
 */
@Immutable
public final class AMR extends Identifier {
	
	
	/**
	 * Creates a new Authentication Method Reference (AMR) with the
	 * specified value.
	 *
	 * @param value The AMR value. Must not be {@code null}.
	 */
	public AMR(final String value) {
	
		super(value);
	}


	@Override
	public boolean equals(final Object object) {
	
		return object instanceof AMR &&
		       this.toString().equals(object.toString());
	}
}

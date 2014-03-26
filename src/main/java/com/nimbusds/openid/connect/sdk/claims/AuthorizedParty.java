package com.nimbusds.openid.connect.sdk.claims;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * OAuth 2.0 client authorized to use the ID Token as an OAuth access token, 
 * if different than the client that requested the ID Token ({@code azp}). It 
 * must contain the {@link com.nimbusds.oauth2.sdk.id.ClientID client 
 * identifier} of the authorised party.
 *
 * <p>The client identifier can be a URI or an arbitrary string.
 *
 * <p>See also {@link com.nimbusds.oauth2.sdk.id.ClientID}.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 2.
 *     <li>OAuth 2.0 (RFC 6749), section 2.2.
 * </ul>
 */
@Immutable
public final class AuthorizedParty extends Identifier {


	/**
	 * Creates a new authorised party identifier with the specified value.
	 *
	 * @param value The authorised party identifier value. Must not be 
	 *              {@code null}.
	 */
	public AuthorizedParty(final String value) {
	
		super(value);
	}


	@Override
	public boolean equals(final Object object) {
	
		return object instanceof AuthorizedParty &&
		       this.toString().equals(object.toString());
	}
}

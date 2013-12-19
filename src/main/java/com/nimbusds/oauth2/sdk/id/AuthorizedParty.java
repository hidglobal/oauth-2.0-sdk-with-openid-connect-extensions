package com.nimbusds.oauth2.sdk.id;


import net.jcip.annotations.Immutable;


/**
 * Authorised party.
 */
@Immutable
public final class AuthorizedParty extends Identifier {


	/**
	 * Creates a new authorised party identifier with the specified value.
	 *
	 * @param value The authorised party value. Must not be {@code null}
	 *              or empty string.
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
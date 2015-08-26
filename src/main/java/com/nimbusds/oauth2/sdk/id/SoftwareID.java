package com.nimbusds.oauth2.sdk.id;


import java.util.UUID;

import net.jcip.annotations.Immutable;


/**
 * Identifier for an OAuth 2.0 client software.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591), section
 *         2.
 * </ul>
 */
@Immutable
public final class SoftwareID extends Identifier {


	/**
	 * Creates a new OAuth 2.0 client software identifier with the
	 * specified value.
	 *
	 * @param value The software identifier value. Must not be {@code null}
	 *              or empty string.
	 */
	public SoftwareID(final String value) {

		super(value);
	}


	/**
	 * Creates a new OAuth 2.0 client software that is a type 4 UUID.
	 */
	public SoftwareID() {

		this(UUID.randomUUID().toString());
	}


	@Override
	public boolean equals(final Object object) {

		return object instanceof SoftwareID &&
		       this.toString().equals(object.toString());
	}
}

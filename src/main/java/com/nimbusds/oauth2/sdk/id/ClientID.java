package com.nimbusds.oauth2.sdk.id;


import net.jcip.annotations.Immutable;


/**
 * Client identifier.
 *
 * <p>Example of a client identifier created from string:
 *
 * <pre>
 * ClientID clientID = new ClientID("client-12345678");
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 2.2.
 * </ul>
 */
@Immutable
public final class ClientID extends Identifier {


	/**
	 * Creates a new client identifier with the specified value.
	 *
	 * @param value The client identifier value. Must not be {@code null}
	 *              or empty string.
	 */
	public ClientID(final String value) {

		super(value);
	}


	/**
	 * Creates a new client identifier with a randomly generated value of 
	 * the specified byte length, Base64URL-encoded.
	 *
	 * @param byteLength The byte length of the value to generate. Must be
	 *                   greater than one.
	 */
	public ClientID(final int byteLength) {
	
		super(byteLength);
	}
	
	
	/**
	 * Creates a new client identifier with a randomly generated 256-bit 
	 * (32-byte) value, Base64URL-encoded.
	 */
	public ClientID() {

		super();
	}


	@Override
	public boolean equals(final Object object) {
	
		return object instanceof ClientID &&
		       this.toString().equals(object.toString());
	}
}
package com.nimbusds.oauth2.sdk.id;


import net.jcip.annotations.Immutable;


/**
 * Client identifier. This class is immutable.
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
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-15)
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
	 * the specified length. The value will be made up of mixed-case 
	 * alphanumeric ASCII characters.
	 *
	 * @param length The number of characters. Must be a positive integer.
	 */
	public ClientID(final int length) {
	
		super(length);
	}
	
	
	/**
	 * Creates a new client identifier with a randomly generated value. The
	 * value will be made up of 32 mixed-case alphanumeric ASCII 
	 * characters.
	 */
	public ClientID() {

		super();
	}


	@Override
	public boolean equals(final Object object) {
	
		return object != null && 
		       object instanceof ClientID && 
		       this.toString().equals(object.toString());
	}
}
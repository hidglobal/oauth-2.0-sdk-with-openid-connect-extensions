package com.nimbusds.openid.connect.sdk;


import net.jcip.annotations.Immutable;

import org.apache.commons.lang3.StringUtils;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Nonce. This is a random, unique string value to associate a user-session 
 * with an ID Token and to mitigate replay attacks. This class is immutable.
 *
 * <p>Example generation of a nonce with eight random mixed-case alphanumeric
 * characters:
 *
 * <pre>
 * Nonce nonce = new Nonce(8);
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.1.1 and 2.1.2.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
@Immutable
public final class Nonce extends Identifier {


	/**
	 * Creates a new nonce with the specified value.
	 *
	 * @param value The nonce value. Must not be {@code null} or empty 
	 *              string.
	 */
	public Nonce(final String value) {
	
		super(value);
	}


	/**
	 * Creates a new nonce with a randomly generated value of the specified
	 * length. The value will be made up of mixed-case alphanumeric ASCII 
	 * characters.
	 *
	 * @param length The number of characters. Must be a positive integer.
	 */
	public Nonce(final int length) {
	
		super(length);
	}
	
	
	/**
	 * Creates a new nonce with a randomly generated value. The value will
	 * be made up of 32 mixed-case alphanumeric ASCII characters.
	 */
	public Nonce() {

		super();
	}
	
	
	@Override
	public boolean equals(final Object object) {
	
		return object != null && 
		       object instanceof Nonce && 
		       this.toString().equals(object.toString());
	}
	
	
	/**
	 * Parses a nonce from the specified string.
	 *
	 * @param s The string to parse, {@code null} or empty if no nonce is
	 *          specified.
	 *
	 * @return The nonce, {@code null} if the parsed string was 
	 *         {@code null} or empty.
	 */
	public static Nonce parse(final String s) {
	
		if (StringUtils.isBlank(s))
			return null;
		
		return new Nonce(s);
	}
}

package com.nimbusds.oauth2.sdk.id;


import java.security.SecureRandom;

import org.apache.commons.lang3.StringUtils;

import org.apache.commons.codec.binary.Base64;

import net.minidev.json.JSONAware;
import net.minidev.json.JSONValue;


/**
 * The base abstract class for representing identifiers and identities. 
 * Provides constructors that generate Base64URL-encoded secure random 
 * identifier values.
 *
 * <p>Extending classes must override the {@link #equals} method.
 *
 * @author Vladimir Dzhuvinov
 */
public abstract class Identifier implements JSONAware {
	
	
	/**
	 * The default byte length of generated identifiers.
	 */
	public static final int DEFAULT_BYTE_LENGTH = 32;
	
	
	/**
	 * The secure random generator.
	 */
	private static final SecureRandom secureRandom = new SecureRandom();


	/**
	 * The identifier value.
	 */
	private final String value;


	/**
	 * Creates a new identifier with the specified value.
	 *
	 * @param value The identifier value. Must not be {@code null} or empty
	 *              string.
	 */
	public Identifier(final String value) {

		if (StringUtils.isBlank(value))
			throw new IllegalArgumentException("The value must not be null or empty string");

		this.value = value;
	}


	/**
	 * Creates a new identifier with a randomly generated value of the 
	 * specified byte length, Base64URL-encoded.
	 *
	 * @param byteLength The byte length of the value to generate. Must be
	 *                   greater than one.
	 */
	public Identifier(final int byteLength) {
		
		if (byteLength < 1)
			throw new IllegalArgumentException("The byte length must be a positive integer");
		
		byte[] n = new byte[byteLength];
		
		secureRandom.nextBytes(n);

		value = Base64.encodeBase64URLSafeString(n);
	}
	
	
	/**
	 * Creates a new identifier with a randomly generated 256-bit 
	 * (32-byte) value, Base64URL-encoded.
	 */
	public Identifier() {

		this(DEFAULT_BYTE_LENGTH);
	}


	/**
	 * Gets the value of this identifier.
	 *
	 * @return The value.
	 */
	public String getValue() {

		return value;
	}


	/**
	 * Returns the JSON string representation of this identifier.
	 *
	 * @return The JSON string.
	 */
	@Override
	public String toJSONString() {

		StringBuilder sb = new StringBuilder("\"");
		sb.append(JSONValue.escape(value));
		sb.append('"');
		return sb.toString();
	}
	
	
	/**
	 * @see #getValue
	 */
	@Override
	public String toString() {
	
		return getValue();
	}


	/**
	 * Overrides {@code Object.hashCode()}.
	 *
	 * @return The object hash code.
	 */
	@Override
	public int hashCode() {
	
		return value.hashCode();
	}
	
	
	/**
	 * Overrides {@code Object.equals()}.
	 *
	 * @param object The object to compare to.
	 *
	 * @return {@code true} if the objects have the same value, otherwise
	 *         {@code false}.
	 */
	@Override
	public abstract boolean equals(final Object object);
}
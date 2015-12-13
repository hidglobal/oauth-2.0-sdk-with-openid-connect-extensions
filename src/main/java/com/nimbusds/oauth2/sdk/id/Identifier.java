package com.nimbusds.oauth2.sdk.id;


import java.io.Serializable;
import java.security.SecureRandom;

import org.apache.commons.lang3.StringUtils;

import com.nimbusds.jose.util.Base64URL;

import net.minidev.json.JSONAware;
import net.minidev.json.JSONValue;


/**
 * The base class for representing identifiers and identities. Provides
 * constructors that generate Base64URL-encoded secure random identifier
 * values.
 *
 * <p>Extending classes must override the {@link #equals} method.
 */
public class Identifier implements Serializable, Comparable<Identifier>, JSONAware {
	
	
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

		value = Base64URL.encode(n).toString();
	}
	
	
	/**
	 * Creates a new identifier with a randomly generated 256-bit 
	 * (32-byte) value, Base64URL-encoded.
	 */
	public Identifier() {

		this(DEFAULT_BYTE_LENGTH);
	}


	/**
	 * Returns the value of this identifier.
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


	@Override
	public int compareTo(final Identifier other) {

		return getValue().compareTo(other.getValue());
	}


	@Override
	public boolean equals(final Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;

		Identifier that = (Identifier) o;

		return getValue() != null ? getValue().equals(that.getValue()) : that.getValue() == null;

	}


	@Override
	public int hashCode() {
		return getValue() != null ? getValue().hashCode() : 0;
	}
}
package com.nimbusds.oauth2.sdk.auth;


import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.Date;

import net.jcip.annotations.Immutable;

import org.apache.commons.codec.binary.Base64;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;


/**
 * Secret or password. The secret should be {@link #erase erased} when no 
 * longer in use.
 */
@Immutable
public final class Secret {
	
	
	/**
	 * The default byte length of generated secrets.
	 */
	public static final int DEFAULT_BYTE_LENGTH = 32;
	
	
	/**
	 * The secure random generator.
	 */
	private static final SecureRandom secureRandom = new SecureRandom();


	/**
	 * The secret value.
	 */
	private byte[] value;


	/**
	 * Optional expiration date.
	 */
	private final Date expDate;


	/**
	 * Creates a new secret with the specified value.
	 *
	 * @param value The secret value. Must not be {@code null} or empty 
	 *              string.
	 */
	public Secret(final String value) {

		this(value, null);
	}


	/**
	 * Creates a new secret with the specified value and expiration date.
	 *
	 * @param value   The secret value. Must be UTF-8 encoded, not 
	 *                {@code null} or empty string.
	 * @param expDate The expiration date, {@code null} if not specified.
	 */
	public Secret(final String value, final Date expDate) {

		if (StringUtils.isBlank(value))
			throw new IllegalArgumentException("The value must not be null or empty string");

		this.value = value.getBytes(Charset.forName("utf-8"));

		this.expDate = expDate;
	}
	
	
	/**
	 * Creates a new secret with a randomly generated value of the 
	 * specified byte length, Base64URL-encoded.
	 *
	 * @param byteLength The byte length of the secret value to generate. 
	 *                   Must be greater than one.
	 */
	public Secret(final int byteLength) {

		this(byteLength, null);
	}


	/**
	 * Creates a new secret with a randomly generated value of the 
	 * specified byte length, Base64URL-encoded, and the specified 
	 * expiration date.
	 *
	 * @param byteLength The byte length of the secret value to generate. 
	 *                   Must be greater than one.
	 * @param expDate    The expiration date, {@code null} if not 
	 *                   specified.
	 */
	public Secret(final int byteLength, final Date expDate) {
	
		if (byteLength < 1)
			throw new IllegalArgumentException("The byte length must be a positive integer");
		
		byte[] n = new byte[byteLength];
		
		secureRandom.nextBytes(n);

		value = Base64.encodeBase64URLSafe(n);
		
		this.expDate = expDate;
	}
	
	
	/**
	 * Creates a new secret with a randomly generated 256-bit (32-byte) 
	 * value, Base64URL-encoded.
	 */
	public Secret() {

		this(DEFAULT_BYTE_LENGTH);
	}


	/**
	 * Gets the value of this secret.
	 *
	 * @return The value as a UTF-8 encoded string, {@code null} if it has 
	 *         been erased.
	 */
	public String getValue() {

		if (ArrayUtils.isEmpty(value))
			return null;
		
		return new String(value, Charset.forName("utf-8"));
	}
	
	
	/**
	 * Gets the value of this secret.
	 *
	 * @return The value as a byte array, {@code null} if it has 
	 *         been erased.
	 */
	public byte[] getValueBytes() {

		return value;
	}


	/**
	 * Erases of the value of this secret.
	 */
	public void erase() {

		if (ArrayUtils.isEmpty(value))
			return;
		
		for (int i=0; i < value.length; i++)
			value[i] = 0;
		
		value = null;
	}


	/**
	 * Gets the expiration date of this secret.
	 *
	 * @return The expiration date, {@code null} if not specified.
	 */
	public Date getExpirationDate() {

		return expDate;
	}


	/**
	 * Checks is this secret has expired.
	 *
	 * @return {@code true} if the secret has an associated expiration date
	 *         which is in the past (according to the current system time), 
	 *         else returns {@code false}.
	 */
	public boolean expired() {

		if (expDate == null)
			return false;

		final Date now = new Date();

		return expDate.before(now);
	}

	
	
	/**
	 * Overrides {@code Object.equals()}.
	 *
	 * @param object The object to compare to.
	 *
	 * @return {@code true} if the objects are secrets the same value, 
	 *         otherwise {@code false}.
	 */
	@Override
	public boolean equals(final Object object) {
	
		return object instanceof Secret &&
		       this.getValue().equals(((Secret)object).getValue());
	}
}
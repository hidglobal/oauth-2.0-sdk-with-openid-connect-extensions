package com.nimbusds.oauth2.sdk.auth;


import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Date;

import com.nimbusds.jose.util.Base64URL;
import net.jcip.annotations.Immutable;
import org.apache.commons.lang3.ArrayUtils;


/**
 * Secret or password. The secret should be {@link #erase erased} when no 
 * longer in use.
 */
@Immutable
public class Secret {
	
	
	/**
	 * The default byte length of generated secrets.
	 */
	public static final int DEFAULT_BYTE_LENGTH = 32;
	
	
	/**
	 * The secure random generator.
	 */
	private static final SecureRandom SECURE_RANDOM = new SecureRandom();


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
	 * @param value The secret value. May be an empty string. Must be
	 *              UTF-8 encoded and not {@code null}.
	 */
	public Secret(final String value) {

		this(value, null);
	}


	/**
	 * Creates a new secret with the specified value and expiration date.
	 *
	 * @param value   The secret value. May be an empty string. Must be
	 *                UTF-8 encoded and not {@code null}.
	 * @param expDate The expiration date, {@code null} if not specified.
	 */
	public Secret(final String value, final Date expDate) {

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
		
		SECURE_RANDOM.nextBytes(n);

		value = Base64URL.encode(n).toString().getBytes(Charset.forName("UTF-8"));
		
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

		if (value == null) {
			return null; // value has been erased
		}

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

		if (value == null) {
			return; // Already erased
		}

		for (int i=0; i < value.length; i++) {
			value[i] = 0;
		}
		
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

		if (expDate == null) {
			return false; // never expires
		}

		final Date now = new Date();

		return expDate.before(now);
	}

	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof Secret)) return false;

		Secret secret = (Secret) o;

		return Arrays.equals(value, secret.value);

	}


	@Override
	public int hashCode() {
		return Arrays.hashCode(value);
	}
}
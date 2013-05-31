package com.nimbusds.oauth2.sdk.auth;


import java.nio.charset.Charset;
import java.util.Date;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;


/**
 * Secret or password. The secret should be {@link #erase erased} when no 
 * longer in use.
 *
 * @author Vladimir Dzhuvinov
 */
public class Secret {


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
	 * @param value The value. Must not be {@code null} or empty string.
	 */
	public Secret(final String value) {

		this(value, null);
	}
	
	
	/**
	 * Creates a new secret with the specified value.
	 *
	 * @param value The value. Must not be {@code null} or empty array.
	 */
	public Secret(final byte[] value) {

		this(value, null);
	}


	/**
	 * Creates a new secret with the specified value and expiration date.
	 *
	 * @param value   The value. Must be UTF-8 encoded, not {@code null} or 
	 * *              empty string.
	 * @param expDate The expiration date, {@code null} if not specified.
	 */
	public Secret(final String value, final Date expDate) {

		if (StringUtils.isBlank(value))
			throw new IllegalArgumentException("The value must not be null or empty string");

		this.value = value.getBytes(Charset.forName("utf-8"));

		this.expDate = expDate;
	}
	
	
	/**
	 * Creates a new secret with the specified value and expiration date.
	 *
	 * @param value   The value. Must not be {@code null} or empty string.
	 * @param expDate The expiration date, {@code null} if not specified.
	 */
	public Secret(final byte[] value, final Date expDate) {

		if (ArrayUtils.isEmpty(value))
			throw new IllegalArgumentException("The value must not be null or empty array");

		this.value = value;
		
		this.expDate = expDate;
	}


	/**
	 * Creates a new secret with a randomly generated value of the 
	 * specified length. The value will be made up of mixed-case 
	 * alphanumeric ASCII characters.
	 *
	 * @param length The number of characters. Must be a positive integer.
	 */
	public Secret(final int length) {
	
		this(RandomStringUtils.randomAlphanumeric(length));
	}
	
	
	/**
	 * Creates a new secret with a randomly generated value. The value will
	 * be made up of 32 mixed-case alphanumeric ASCII characters.
	 */
	public Secret() {

		this(32);
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

		if (expDate.after(now))
			return false;
		else
			return true;
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
	
		return object != null && 
		       object instanceof Secret && 
		       this.getValue().equals(((Secret)object).getValue());
	}
}
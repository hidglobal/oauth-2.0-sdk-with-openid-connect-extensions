package com.nimbusds.oauth2.sdk.auth;


import java.util.Date;

import org.apache.commons.lang3.RandomStringUtils;

import com.nimbusds.oauth2.sdk.util.StringUtils;


/**
 * Secret or password. The secret should be {@link #erase}d once no longer in
 * use.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-28)
 */
public class Secret {


	/**
	 * The secret value.
	 */
	private String value;


	/**
	 * Optional expiration date.
	 */
	private Date expDate;


	/**
	 * Creates a new secret with the specified value.
	 *
	 * @param value The value. Must not be {@code null} or empty string.
	 */
	public Secret(final String value) {

		this(value, null);
	}


	/**
	 * Creates a new secret with the specified value and expiration date.
	 *
	 * @param value   The value. Must not be {@code null} or empty string.
	 * @param expDate The expiration date, {@code null} if not specified.
	 */
	public Secret(final String value, final Date expDate) {

		if (StringUtils.isUndefined(value))
			throw new IllegalArgumentException("The value must not be null or empty string");

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
	 * @return The value, {@code null} if it has been erased.
	 */
	public String getValue() {

		return value;
	}


	/**
	 * Erases of the value of this secret.
	 */
	public void erase() {

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
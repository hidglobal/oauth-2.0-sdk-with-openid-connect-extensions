package com.nimbusds.oauth2.sdk.id;


import java.net.URI;
import java.net.URISyntaxException;

import net.jcip.annotations.Immutable;


/**
 * Issuer identifier.
 *
 * <p>Valid issuer identifiers are URIs with "https" schema and no query or
 * fragment component.
 */
@Immutable
public final class Issuer extends Identifier {


	/**
	 * Checks if the specified string represents a valid issuer identifier.
	 * This method is {@code null}-safe.
	 *
	 * @param value The issuer string.
	 *
	 * @return {@code true} if the string represents a valid issuer
	 *         identifier, else {@code false}.
	 */
	public static boolean isValid(final String value) {

		if (value == null)
			return false;

		try {
			return isValid(new URI(value));

		} catch (URISyntaxException e) {

			return false;
		}
	}


	/**
	 * Checks if the specified issuer is a valid identifier. This method is
	 * {@code null}-safe.
	 *
	 * @param value The issuer.
	 *
	 * @return {@code true} if the value is a valid identifier, else
	 *         {@code false}.
	 */
	public static boolean isValid(final Issuer value) {

		if (value == null)
			return false;

		try {
			return isValid(new URI(value.getValue()));

		} catch (URISyntaxException e) {

			return false;
		}
	}


	/**
	 * Checks if the specified URI represents a valid issuer identifier.
	 * This method is {@code null}-safe.
	 *
	 * @param value The URI.
	 *
	 * @return {@code true} if the values represents a valid issuer
	 *         identifier, else {@code false}.
	 */
	public static boolean isValid(final URI value) {

		if (value == null)
			return false;

		if (value.getScheme() == null || ! value.getScheme().equalsIgnoreCase("https"))
			return false;

		if (value.getRawQuery() != null)
			return false;

		if (value.getRawFragment() != null)
			return false;

		return true;
	}


	/**
	 * Creates a new issuer identifier with the specified value.
	 *
	 * @param value The issuer identifier value. Must not be {@code null}
	 *              or empty string.
	 */
	public Issuer(final String value) {

		super(value);
	}


	/**
	 * Creates a new issuer identifier with the specified URI value.
	 *
	 * @param value The URI value. Must not be {@code null}.
	 */
	public Issuer(final URI value) {

		super(value.toString());
	}


	/**
	 * Creates a new issuer identifier with the specified value.
	 *
	 * @param value The value. Must not be {@code null}.
	 */
	public Issuer(final Identifier value) {

		super(value.getValue());
	}


	/**
	 * Checks if this issuer is a valid identifier. This method is
	 * {@code null}-safe.
	 *
	 * @return {@code true} if the value is a valid identifier, else
	 *         {@code false}.
	 */
	public boolean isValid() {

		return Issuer.isValid(this);
	}


	@Override
	public boolean equals(final Object object) {
	
		return object instanceof Issuer && this.toString().equals(object.toString());
	}
}
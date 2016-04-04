package com.nimbusds.oauth2.sdk.pkce;


import com.nimbusds.oauth2.sdk.auth.Secret;


/**
 * Authorisation code verifier.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Proof Key for Code Exchange by OAuth Public Clients (RFC 7636).
 * </ul>
 */
public class CodeVerifier extends Secret {


	/**
	 * The minimal character length of a code verifier.
	 */
	public static final int MIN_LENGTH = 43;


	/**
	 * The maximum character length of a code verifier.
	 */
	public static final int MAX_LENGTH = 128;
	

	/**
	 * Creates a new code verifier with the specified value.
	 *
	 * @param value The code verifier value. Must not contain characters
	 *              other than [A-Z] / [a-z] / [0-9] / "-" / "." / "_" /
	 *              "~". The verifier length must be at least 43
	 *              characters but not more than 128 characters. Must not
	 *              be {@code null} or empty string.
	 */
	public CodeVerifier(final String value) {
		super(value);

		if (value.length() < MIN_LENGTH) {
			throw new IllegalArgumentException("The code verifier must be at least " + MIN_LENGTH + " characters");
		}

		if (value.length() > MAX_LENGTH) {
			throw new IllegalArgumentException("The code verifier must not be longer than " + MAX_LENGTH + " characters");
		}
	}


	/**
	 * Creates a new code verifier with the minimum (43 character) length.
	 */
	public CodeVerifier() {
		super(32);
	}


	@Override
	public boolean equals(final Object object) {
		return object instanceof CodeVerifier && super.equals(object);
	}
}

package com.nimbusds.oauth2.sdk.pkce;


import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Authorisation code challenge.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Proof Key for Code Exchange by OAuth Public Clients (RFC 7636).
 * </ul>
 */
public class CodeChallenge extends Identifier {
	

	/**
	 * Creates a new code challenge with the specified value.
	 *
	 * @param value The code challenge value. Must not be {@code null} or
	 *              empty string.
	 */
	public CodeChallenge(final String value) {
		super(value);
	}


	/**
	 * Computes the code challenge using the specified method and verifier.
	 *
	 * @param method       The code challenge method. Must be supported and
	 *                     not {@code null}.
	 * @param codeVerifier The code verifier. Must not be {@code null}.
	 *
	 * @return The computed code challenge.
	 */
	public static CodeChallenge compute(final CodeChallengeMethod method, final CodeVerifier codeVerifier) {

		if (CodeChallengeMethod.PLAIN.equals(method)) {
			return new CodeChallenge(codeVerifier.getValue());
		}

		if (CodeChallengeMethod.S256.equals(method)) {

			MessageDigest md;

			try {
				md = MessageDigest.getInstance("SHA-256");
			} catch (NoSuchAlgorithmException e) {
				throw new IllegalStateException(e.getMessage());
			}

			byte[] hash = md.digest(codeVerifier.getValueBytes());

			return new CodeChallenge(Base64URL.encode(hash).toString());
		}

		throw new IllegalArgumentException("Unsupported code challenge method: " + method);
	}
}

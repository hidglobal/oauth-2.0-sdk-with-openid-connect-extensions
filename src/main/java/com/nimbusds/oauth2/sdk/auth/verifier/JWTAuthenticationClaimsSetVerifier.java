package com.nimbusds.oauth2.sdk.auth.verifier;


import java.util.Set;

import net.jcip.annotations.Immutable;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;

import com.nimbusds.oauth2.sdk.assertions.jwt.JWTAssertionClaimsSetVerifier;
import com.nimbusds.oauth2.sdk.id.Audience;


/**
 * JWT client authentication claims set verifier.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 9.
 *     <li>JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7523).
 * </ul>
 */
@Immutable
class JWTAuthenticationClaimsSetVerifier extends JWTAssertionClaimsSetVerifier {

	// Cache JWT exceptions for quick processing of bad claims

	/**
	 * Missing or invalid JWT claim exception.
	 */
	private static BadJWTException INVALID_CLAIM_EXCEPTION =
		new BadJWTException("Missing or invalid JWT claim");


	/**
	 * Creates a new JWT client authentication claims set verifier.
	 *
	 * @param expectedAudience The permitted audience (aud) claim values.
	 *                         Must not be empty or {@code null}. Should
	 *                         typically contain the token endpoint URI and
	 *                         for OpenID provider it may also include the
	 *                         issuer URI.
	 */
	public JWTAuthenticationClaimsSetVerifier(final Set<Audience> expectedAudience) {

		super(expectedAudience);
	}


	@Override
	public void verify(final JWTClaimsSet claimsSet)
		throws BadJWTException {

		super.verify(claimsSet);

		// iss == sub
		if (! claimsSet.getIssuer().equals(claimsSet.getSubject())) {
			throw INVALID_CLAIM_EXCEPTION;
		}
	}
}

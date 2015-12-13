package com.nimbusds.oauth2.sdk.assertions.jwt;


import java.util.Set;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.oauth2.sdk.id.Audience;
import net.jcip.annotations.Immutable;


/**
 * JSON Web Token (JWT) bearer assertion details (claims set) verifier for
 * OAuth 2.0 client authentication and authorisation grants.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7523).
 * </ul>
 */
@Immutable
public class JWTAssertionDetailsVerifier extends DefaultJWTClaimsVerifier {


	// Cache JWT exceptions for quick processing of bad claims sets


	/**
	 * Missing JWT expiration claim.
	 */
	private static BadJWTException MISSING_EXP_CLAIM_EXCEPTION =
		new BadJWTException("Missing JWT expiration claim");


	/**
	 * Missing JWT audience claim.
	 */
	private static BadJWTException MISSING_AUD_CLAIM_EXCEPTION =
		new BadJWTException("Missing JWT audience claim");


	/**
	 * Missing JWT subject claim.
	 */
	private static BadJWTException MISSING_SUB_CLAIM_EXCEPTION =
		new BadJWTException("Missing JWT subject claim");


	/**
	 * Missing JWT issuer claim.
	 */
	private static BadJWTException MISSING_ISS_CLAIM_EXCEPTION =
		new BadJWTException("Missing JWT issuer claim");


	/**
	 * The expected audience.
	 */
	private final Set<Audience> expectedAudience;


	/**
	 * Cached unexpected JWT audience claim exception.
	 */
	private final BadJWTException unexpectedAudClaimException;


	/**
	 * Creates a new JWT bearer assertion details (claims set) verifier.
	 *
	 * @param expectedAudience The permitted audience (aud) claim values.
	 *                         Must not be empty or {@code null}. Should
	 *                         typically contain the token endpoint URI and
	 *                         for OpenID provider it may also include the
	 *                         issuer URI.
	 */
	public JWTAssertionDetailsVerifier(final Set<Audience> expectedAudience) {

		if (expectedAudience == null || expectedAudience.isEmpty()) {
			throw new IllegalArgumentException("The expected audience set must not be null or empty");
		}

		this.expectedAudience = expectedAudience;

		unexpectedAudClaimException = new BadJWTException("Invalid JWT audience claim, expected " + expectedAudience);
	}


	/**
	 * Returns the permitted audience values.
	 *
	 * @return The permitted audience (aud) claim values.
	 */
	public Set<Audience> getExpectedAudience() {

		return expectedAudience;
	}


	@Override
	public void verify(final JWTClaimsSet claimsSet)
		throws BadJWTException {

		super.verify(claimsSet);

		if (claimsSet.getExpirationTime() == null) {
			throw MISSING_EXP_CLAIM_EXCEPTION;
		}

		if (claimsSet.getAudience() == null || claimsSet.getAudience().isEmpty()) {
			throw MISSING_AUD_CLAIM_EXCEPTION;
		}

		boolean audMatch = false;

		for (String aud: claimsSet.getAudience()) {

			if (aud == null || aud.isEmpty()) {
				continue; // skip
			}

			if (expectedAudience.contains(new Audience(aud))) {
				audMatch = true;
			}
		}

		if (! audMatch) {
			throw unexpectedAudClaimException;
		}

		if (claimsSet.getIssuer() == null) {
			throw MISSING_ISS_CLAIM_EXCEPTION;
		}

		if (claimsSet.getSubject() == null) {
			throw MISSING_SUB_CLAIM_EXCEPTION;
		}
	}
}

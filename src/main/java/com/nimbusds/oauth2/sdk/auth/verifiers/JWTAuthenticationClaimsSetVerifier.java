package com.nimbusds.oauth2.sdk.auth.verifiers;


import java.util.Set;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;

import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import net.jcip.annotations.Immutable;


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
public class JWTAuthenticationClaimsSetVerifier extends DefaultJWTClaimsVerifier {


	/**
	 * The expected client identifier.
	 */
	private final ClientID expectedClientID;


	/**
	 * The expected audience.
	 */
	private final Set<Audience> expectedAudience;


	/**
	 * Creates a new JWT client authentication claims set verifier.
	 *
	 * @param expectedClientID The expected client identifier. Used for
	 *                         issuer (iss) and subject (sub) claims
	 *                         checking. Must not be {@code null}.
	 * @param expectedAudience The possible expected audience (aud). Must
	 *                         not be empty or {@code null}. Typically the
	 *                         token endpoint URI and the issuer URI for
	 *                         OpenID providers.
	 */
	public JWTAuthenticationClaimsSetVerifier(final ClientID expectedClientID,
						  final Set<Audience> expectedAudience) {

		if (expectedClientID == null) {
			throw new IllegalArgumentException("The expected client ID must not be null");
		}

		this.expectedClientID = expectedClientID;

		if (expectedAudience == null || expectedAudience.isEmpty()) {
			throw new IllegalArgumentException("The expected audience set must not be null or empty");
		}

		this.expectedAudience = expectedAudience;
	}


	@Override
	public void verify(final JWTClaimsSet claimsSet)
		throws BadJWTException {

		super.verify(claimsSet);

		if (claimsSet.getExpirationTime() == null) {
			throw new BadJWTException("Missing required expiration (exp) claim");
		}

		if (! expectedClientID.getValue().equals(claimsSet.getIssuer())) {
			throw new BadJWTException("Missing or unexpected issuer (iss) claim");
		}

		if (! expectedClientID.getValue().equals(claimsSet.getSubject())) {
			throw new BadJWTException("Missing or unexpected subject (sub) claim");
		}

		if (claimsSet.getAudience() == null || claimsSet.getAudience().isEmpty()) {
			throw new BadJWTException("Missing audience (aud) claim");
		}

		if (claimsSet.getAudience().size() > 1) {
			throw new BadJWTException("The audience (aud) claim must be singular");
		}

		Audience aud = new Audience(claimsSet.getAudience().get(0));

		if (! expectedAudience.contains(aud)) {
			throw new BadJWTException("Unxpected audience (aud): " + aud);
		}
	}
}

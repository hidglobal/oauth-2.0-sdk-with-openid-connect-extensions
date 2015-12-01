package com.nimbusds.openid.connect.sdk.token.verifiers;


import java.util.Date;
import java.util.List;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.JWTClaimsVerifier;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.Nonce;
import net.jcip.annotations.ThreadSafe;


/**
 * ID token claims verifier.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 3.1.3.7 for code flow.
 *     <li>OpenID Connect Core 1.0, section 3.2.2.11 for implicit flow.
 *     <li>OpenID Connect Core 1.0, sections 3.3.2.12 and 3.3.3.7 for hybrid
 *         flow.
 * </ul>
 */
@ThreadSafe
public class IDTokenClaimsVerifier implements JWTClaimsVerifier {


	// Cache general exceptions
	/**
	 * Missing {@code exp} claim exception.
	 */
	private static final BadJWTException MISSING_EXP_CLAIM_EXCEPTION =
		new BadJWTException("Missing JWT expiration (exp) claim");


	/**
	 * Missing {@code iat} claim exception.
	 */
	private static final BadJWTException MISSING_IAT_CLAIM_EXCEPTION =
		new BadJWTException("Missing JWT issue time (iat) claim");


	/**
	 * Missing {@code iss} claim exception.
	 */
	private static final BadJWTException MISSING_ISS_CLAIM_EXCEPTION =
		new BadJWTException("Missing JWT issuer (iss) claim");


	/**
	 * Missing {@code sub} claim exception.
	 */
	private static final BadJWTException MISSING_SUB_CLAIM_EXCEPTION =
		new BadJWTException("Missing JWT subject (sub) claim");


	/**
	 * Missing {@code aud} claim exception.
	 */
	private static final BadJWTException MISSING_AUD_CLAIM_EXCEPTION =
		new BadJWTException("Missing JWT audience (aud) claim");


	/**
	 * Missing {@code nonce} claim exception.
	 */
	private static final BadJWTException MISSING_NONCE_CLAIM_EXCEPTION =
		new BadJWTException("Missing JWT nonce (nonce) claim");


	/**
	 * Expired ID token exception.
	 */
	private static final BadJWTException EXPIRED_EXCEPTION =
		new BadJWTException("Expired JWT");


	/**
	 * ID token issue time ahead of current time exception.
	 */
	private static final BadJWTException IAT_CLAIM_AHEAD_EXCEPTION =
		new BadJWTException("JWT issue time ahead of current time");
	

	/**
	 * The expected ID token issuer.
	 */
	private final Issuer expectedIssuer;


	/**
	 * The requesting client.
	 */
	private final ClientID expectedClientID;


	/**
	 * The expected nonce, {@code null} if not required or specified.
	 */
	private final Nonce expectedNonce;


	/**
	 * Creates a new ID token claims verifier.
	 *
	 * @param issuer   The expected ID token issuer. Must not be
	 *                 {@code null}.
	 * @param clientID The client ID. Must not be {@code null}.
	 * @param nonce    The nonce, required in the implicit flow or for
	 *                 ID tokens returned by the authorisation endpoint in
	 *                 the hybrid flow. {@code null} if not required or
	 *                 specified.
	 */
	public IDTokenClaimsVerifier(final Issuer issuer, final ClientID clientID, final Nonce nonce) {

		if (issuer == null) {
			throw new IllegalArgumentException("The expected ID token issuer must not be null");
		}
		this.expectedIssuer = issuer;

		if (clientID == null) {
			throw new IllegalArgumentException("The client ID must not be null");
		}
		this.expectedClientID = clientID;

		this.expectedNonce = nonce;
	}


	/**
	 * Returns the expected ID token issuer.
	 *
	 * @return The ID token issuer.
	 */
	public Issuer getExpectedIssuer() {

		return expectedIssuer;
	}


	/**
	 * Returns the client ID for verifying the ID token audience.
	 *
	 * @return The client ID.
	 */
	public ClientID getClientID() {

		return expectedClientID;
	}


	/**
	 * Returns the expected nonce.
	 *
	 * @return The nonce, {@code null} if not required or specified.
	 */
	public Nonce getExpectedNonce() {

		return expectedNonce;
	}


	@Override
	public void verify(final JWTClaimsSet claimsSet)
		throws BadJWTException {

		// See http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation

		final String tokenIssuer = claimsSet.getIssuer();

		if (tokenIssuer == null) {
			throw MISSING_ISS_CLAIM_EXCEPTION;
		}

		if (! expectedIssuer.getValue().equals(tokenIssuer)) {
			throw new BadJWTException("Unexpected JWT issuer: " + tokenIssuer);
		}

		if (claimsSet.getSubject() == null) {
			throw MISSING_SUB_CLAIM_EXCEPTION;
		}

		final List<String> tokenAudience = claimsSet.getAudience();

		if (tokenAudience == null || tokenAudience.isEmpty()) {
			throw MISSING_AUD_CLAIM_EXCEPTION;
		}

		if (! tokenAudience.contains(expectedClientID.getValue())) {
			throw new BadJWTException("Unexpected JWT audience: " + tokenAudience);
		}


		if (tokenAudience.size() > 1) {

			final String tokenAzp;

			try {
				tokenAzp = claimsSet.getStringClaim("azp");
			} catch (java.text.ParseException e) {
				throw new BadJWTException("Invalid JWT authorized party (azp) claim: " + e.getMessage());
			}

			if (tokenAzp != null) {
				if (! expectedClientID.getValue().equals(tokenAzp)) {
					throw new BadJWTException("Unexpected JWT authorized party (azp) claim: " + tokenAzp);
				}
			}
		}

		final Date exp = claimsSet.getExpirationTime();

		if (exp == null) {
			throw MISSING_EXP_CLAIM_EXCEPTION;
		}

		final Date iat = claimsSet.getIssueTime();

		if (iat == null) {
			throw MISSING_IAT_CLAIM_EXCEPTION;
		}


		final Date now = new Date();

		if (exp.before(now)) {
			throw EXPIRED_EXCEPTION;
		}

		if (iat.after(now)) {
			throw IAT_CLAIM_AHEAD_EXCEPTION;
		}


		if (expectedNonce != null) {

			final String tokenNonce;

			try {
				tokenNonce = claimsSet.getStringClaim("nonce");
			} catch (java.text.ParseException e) {
				throw new BadJWTException("Invalid JWT nonce (nonce) claim: " + e.getMessage());
			}

			if (tokenNonce == null) {
				throw MISSING_NONCE_CLAIM_EXCEPTION;
			}

			if (! expectedNonce.getValue().equals(tokenNonce)) {
				throw new BadJWTException("Unexpected JWT nonce (nonce) claim: " + tokenNonce);
			}
		}
	}
}

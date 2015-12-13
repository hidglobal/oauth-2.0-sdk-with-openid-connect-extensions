package com.nimbusds.oauth2.sdk.assertions.saml2;


import java.util.Date;
import java.util.Set;

import com.nimbusds.jwt.proc.ClockSkewAware;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.id.Audience;
import net.jcip.annotations.Immutable;
import org.apache.commons.collections4.CollectionUtils;


/**
 * SAML 2.0 bearer assertion details verifier for OAuth 2.0 client
 * authentication and authorisation grants. Intended for initial validation of
 * SAML 2.0 assertions:
 *
 * <ul>
 *     <li>Audience check
 *     <li>Expiration time check
 *     <li>Not-before time check (is set)
 * </ul>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Security Assertion Markup Language (SAML) 2.0 Profile for OAuth 2.0
 *         Client Authentication and Authorization Grants (RFC 7522).
 * </ul>
 */
@Immutable
public class SAML2AssertionDetailsVerifier implements ClockSkewAware {


	/**
	 * The default maximum acceptable clock skew, in seconds (60).
	 */
	public static final int DEFAULT_MAX_CLOCK_SKEW_SECONDS = 60;
	

	// Cache SAML exceptions to speed up processing


	/**
	 * Expired SAML 2.0 assertion exception.
	 */
	private static final BadSAML2AssertionException EXPIRED_SAML2_ASSERTION_EXCEPTION =
		new BadSAML2AssertionException("Expired SAML 2.0 assertion");


	/**
	 * SAML 2.0 assertion before use time.
	 */
	private static final BadSAML2AssertionException SAML2_ASSERTION_BEFORE_USE_EXCEPTION =
		new BadSAML2AssertionException("SAML 2.0 assertion before use time");


	/**
	 * The expected audience.
	 */
	private final Set<Audience> expectedAudience;


	/**
	 * Cached unexpected SAML 2.0 audience exception.
	 */
	private final BadSAML2AssertionException unexpectedAudienceException;


	/**
	 * The maximum acceptable clock skew, in seconds.
	 */
	private int maxClockSkewSeconds = DEFAULT_MAX_CLOCK_SKEW_SECONDS;


	/**
	 * Creates a new SAML 2.0 bearer assertion details verifier.
	 *
	 * @param expectedAudience The expected audience values. Must not be
	 *                         empty or {@code null}. Should typically
	 *                         contain the token endpoint URI and for
	 *                         OpenID provider it may also include the
	 *                         issuer URI.
	 */
	public SAML2AssertionDetailsVerifier(final Set<Audience> expectedAudience) {
		if (CollectionUtils.isEmpty(expectedAudience)) {
			throw new IllegalArgumentException("The expected audience set must not be null or empty");
		}

		this.expectedAudience = expectedAudience;

		unexpectedAudienceException = new BadSAML2AssertionException("Invalid SAML 2.0 audience, expected " + expectedAudience);
	}


	/**
	 * Returns the expected audience values.
	 *
	 * @return The expected audience values.
	 */
	public Set<Audience> getExpectedAudience() {
		return expectedAudience;
	}


	@Override
	public int getMaxClockSkew() {
		return maxClockSkewSeconds;
	}


	@Override
	public void setMaxClockSkew(int maxClockSkewSeconds) {
		this.maxClockSkewSeconds = maxClockSkewSeconds;
	}


	/**
	 * Verifies the specified SAML 2.0 bearer assertion details.
	 *
	 * @param assertionDetails The SAML 2.0 bearer assertion details. Must
	 *                         not be {@code null}.
	 *
	 * @throws BadSAML2AssertionException If verification didn't pass
	 *                                    successfully.
	 */
	public void verify(final SAML2AssertionDetails assertionDetails)
		throws BadSAML2AssertionException {

		// Check audience
		if (! Audience.matchesAny(expectedAudience, assertionDetails.getAudience())) {
			throw unexpectedAudienceException;
		}

		// Check expiration
		final Date now = new Date();

		if (! DateUtils.isAfter(assertionDetails.getExpirationTime(), now, maxClockSkewSeconds)) {
			throw EXPIRED_SAML2_ASSERTION_EXCEPTION;
		}

		// Check optional not before use time
		if (assertionDetails.getNotBeforeTime() != null) {
			if (! DateUtils.isBefore(assertionDetails.getNotBeforeTime(), now, maxClockSkewSeconds))
				throw SAML2_ASSERTION_BEFORE_USE_EXCEPTION;
		}
	}
}

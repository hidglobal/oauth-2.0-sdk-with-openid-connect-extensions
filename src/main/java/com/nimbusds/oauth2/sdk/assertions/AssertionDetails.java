package com.nimbusds.oauth2.sdk.assertions;


import java.util.Date;
import java.util.List;

import com.nimbusds.oauth2.sdk.id.*;


/**
 * Common assertion details used in JWT bearer assertions and SAML 2.0 bearer
 * assertions.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Assertion Framework for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7521), section 5.1.
 * </ul>
 */
public abstract class AssertionDetails {
	

	/**
	 * The issuer (required).
	 */
	private final Issuer issuer;


	/**
	 * The subject (required).
	 */
	private final Subject subject;


	/**
	 * The audience that this assertion is intended for (required).
	 */
	private final List<Audience> audience;


	/**
	 * The time at which this assertion was issued (optional).
	 */
	private final Date iat;


	/**
	 * The expiration time that limits the time window during which the
	 * assertion can be used (required).
	 */
	private final Date exp;


	/**
	 * Unique identifier for the assertion (optional). The identifier may
	 * be used by implementations requiring message de-duplication for
	 * one-time use assertions.
	 */
	private final Identifier id;


	/**
	 * Creates a new assertion details instance.
	 *
	 * @param issuer   The issuer. Must not be {@code null}.
	 * @param subject  The subject. Must not be {@code null}.
	 * @param audience The audience, typically including the URI of the
	 *                 authorisation server's token endpoint. Must not be
	 *                 {@code null}.
	 * @param exp      The expiration time. Must not be {@code null}.
	 * @param iat      The time at which the assertion was issued,
	 *                 {@code null} if not specified.
	 * @param id       Unique identifier for the assertion, {@code null} if
	 *                 not specified.
	 */
	public AssertionDetails(final Issuer issuer,
				final Subject subject,
				final List<Audience> audience,
				final Date iat,
				final Date exp,
				final Identifier id) {
		if (issuer == null)
			throw new IllegalArgumentException("The issuer must not be null");

		this.issuer = issuer;

		if (subject == null)
			throw new IllegalArgumentException("The subject must not be null");

		this.subject = subject;


		if (audience == null || audience.isEmpty())
			throw new IllegalArgumentException("The audience must not be null or empty");

		this.audience = audience;


		if (exp == null)
			throw new IllegalArgumentException("The expiration time must not be null");
		this.exp = exp;

		this.iat = iat;

		this.id = id;
	}
	
	
	/**
	 * Returns the issuer.
	 *
	 * @return The issuer.
	 */
	public Issuer getIssuer() {
		
		return issuer;
	}
	
	
	/**
	 * Returns the subject.
	 *
	 * @return The subject.
	 */
	public Subject getSubject() {
		
		return subject;
	}
	
	
	/**
	 * Returns the audience.
	 *
	 * @return The audience, typically including the URI of the
	 *         authorisation server's token endpoint.
	 */
	public List<Audience> getAudience() {
		
		return audience;
	}
	
	
	/**
	 * Returns the expiration time.
	 *
	 * @return The expiration time.
	 */
	public Date getExpirationTime() {
		
		return exp;
	}
	
	
	/**
	 * Returns the optional issue time.
	 *
	 * @return The issue time, {@code null} if not specified.
	 */
	public Date getIssueTime() {
		
		return iat;
	}
	
	
	/**
	 * Returns the optional assertion identifier.
	 *
	 * @return The identifier, {@code null} if not specified.
	 */
	public Identifier getID() {
		
		return id;
	}
}

package com.nimbusds.oauth2.sdk.assertions.saml2;


import java.util.Collections;
import java.util.Date;
import java.util.HashSet;

import com.nimbusds.jwt.proc.ClockSkewAware;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import junit.framework.TestCase;


/**
 * Tests the SAML 2.0 assertion details verifier.
 */
public class SAML2AssertionDetailsVerifierTest extends TestCase{
	

	public void testClockSkewSettings() {

		assertEquals(60, SAML2AssertionDetailsVerifier.DEFAULT_MAX_CLOCK_SKEW_SECONDS);

		SAML2AssertionDetailsVerifier verifier = new SAML2AssertionDetailsVerifier(
			new HashSet<>(Collections.singletonList(new Audience("https://c2id.com/token"))));

		assertTrue(verifier instanceof ClockSkewAware);

		assertEquals(SAML2AssertionDetailsVerifier.DEFAULT_MAX_CLOCK_SKEW_SECONDS, verifier.getMaxClockSkew());
		verifier.setMaxClockSkew(120);
		assertEquals(120, verifier.getMaxClockSkew());
	}


	public void testGood()
		throws BadSAML2AssertionException {

		SAML2AssertionDetailsVerifier verifier = new SAML2AssertionDetailsVerifier(
			new HashSet<>(Collections.singletonList(new Audience("https://c2id.com/token"))));

		assertTrue(verifier.getExpectedAudience().contains(new Audience("https://c2id.com/token")));

		SAML2AssertionDetails details = new SAML2AssertionDetails(
			new Issuer("123"),
			new Subject("alice"),
			new Audience("https://c2id.com/token"));

		verifier.verify(details);
	}


	public void testExpired() {

		SAML2AssertionDetailsVerifier verifier = new SAML2AssertionDetailsVerifier(
			new HashSet<>(Collections.singletonList(new Audience("https://c2id.com/token"))));

		verifier.setMaxClockSkew(0);

		final Date now = new Date();
		final Date oneHourAgo = new Date(now.getTime() - 60*60*1000L);
		final Date twoHoursAgo = new Date(now.getTime() - 2*60*60*1000L);

		SAML2AssertionDetails details = new SAML2AssertionDetails(
			new Issuer("123"),
			new Subject("alice"),
			null,
			twoHoursAgo,
			null,
			new Audience("https://c2id.com/token").toSingleAudienceList(),
			oneHourAgo,
			twoHoursAgo,
			twoHoursAgo,
			new Identifier(),
			null, null);

		try {
			verifier.verify(details);
			fail();
		} catch (BadSAML2AssertionException e) {
			assertEquals("Expired SAML 2.0 assertion", e.getMessage());
		}
	}


	public void testNotBeforeWithSkew()
		throws BadSAML2AssertionException {

		SAML2AssertionDetailsVerifier verifier = new SAML2AssertionDetailsVerifier(
			new HashSet<>(Collections.singletonList(new Audience("https://c2id.com/token"))));

		verifier.setMaxClockSkew(60);

		final Date now = new Date();
		final Date thirtySecondsAhead = new Date(now.getTime() + 30*1000L);
		final Date in5Mins = new Date(now.getTime() + 5*60*1000L);

		SAML2AssertionDetails details = new SAML2AssertionDetails(
			new Issuer("123"),
			new Subject("alice"),
			null,
			now,
			null,
			new Audience("https://c2id.com/token").toSingleAudienceList(),
			in5Mins,
			thirtySecondsAhead,
			thirtySecondsAhead,
			new Identifier(),
			null, null);

		verifier.verify(details);
	}


	public void testExpiredWithSkew()
		throws BadSAML2AssertionException {

		SAML2AssertionDetailsVerifier verifier = new SAML2AssertionDetailsVerifier(
			new HashSet<>(Collections.singletonList(new Audience("https://c2id.com/token"))));

		verifier.setMaxClockSkew(60);

		final Date now = new Date();
		final Date thirtySecondsAhead = new Date(now.getTime() + 30*1000L);

		SAML2AssertionDetails details = new SAML2AssertionDetails(
			new Issuer("123"),
			new Subject("alice"),
			null,
			now,
			null,
			new Audience("https://c2id.com/token").toSingleAudienceList(),
			thirtySecondsAhead,
			now,
			now,
			new Identifier(),
			null, null);

		verifier.verify(details);
	}
}

package com.nimbusds.openid.connect.sdk.token.verifiers;


import java.util.Arrays;
import java.util.Date;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.Nonce;
import junit.framework.TestCase;


/**
 * Tests the ID token claims verifier.
 */
public class IDTokenClaimsVerifierTest extends TestCase {
	

	public void testHappyMinimalWithNonce()
		throws BadJWTException {

		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Nonce nonce = new Nonce("xyz");

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, nonce, 0);

		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		assertEquals(nonce, verifier.getExpectedNonce());

		Date now = new Date();
		Date iat = new Date(now.getTime() - 5*60*1000);
		Date exp = new Date(now.getTime() + 5*60*1000);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.subject("alice")
			.audience(clientID.getValue())
			.expirationTime(exp)
			.issueTime(iat)
			.claim("nonce", nonce.getValue())
			.build();

		verifier.verify(claimsSet);
	}


	public void testHappyMinimalWithoutNonce()
		throws BadJWTException {

		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, null, 0);

		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		assertNull(verifier.getExpectedNonce());

		Date now = new Date();
		Date iat = new Date(now.getTime() - 5*60*1000);
		Date exp = new Date(now.getTime() + 5*60*1000);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.subject("alice")
			.audience(clientID.getValue())
			.expirationTime(exp)
			.issueTime(iat)
			.build();

		verifier.verify(claimsSet);
	}


	public void testMissingIssuer() {

		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, null, 0);

		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		assertNull(verifier.getExpectedNonce());

		Date now = new Date();
		Date iat = new Date(now.getTime() - 5*60*1000);
		Date exp = new Date(now.getTime() + 5*60*1000);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.audience(clientID.getValue())
			.expirationTime(exp)
			.issueTime(iat)
			.build();

		try {
			verifier.verify(claimsSet);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Missing JWT issuer (iss) claim", e.getMessage());
		}
	}


	public void testMissingSubject() {

		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, null, 0);

		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		assertNull(verifier.getExpectedNonce());

		Date now = new Date();
		Date iat = new Date(now.getTime() - 5*60*1000);
		Date exp = new Date(now.getTime() + 5*60*1000);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.audience(clientID.getValue())
			.expirationTime(exp)
			.issueTime(iat)
			.build();

		try {
			verifier.verify(claimsSet);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Missing JWT subject (sub) claim", e.getMessage());
		}
	}


	public void testMissingAudience() {

		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, null, 0);

		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		assertNull(verifier.getExpectedNonce());

		Date now = new Date();
		Date iat = new Date(now.getTime() - 5*60*1000);
		Date exp = new Date(now.getTime() + 5*60*1000);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.subject("alice")
			.expirationTime(exp)
			.issueTime(iat)
			.build();

		try {
			verifier.verify(claimsSet);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Missing JWT audience (aud) claim", e.getMessage());
		}
	}


	public void testMissingExpirationTime() {

		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, null, 0);

		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		assertNull(verifier.getExpectedNonce());

		Date now = new Date();
		Date iat = new Date(now.getTime() - 5*60*1000);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.subject("alice")
			.audience(clientID.getValue())
			.issueTime(iat)
			.build();

		try {
			verifier.verify(claimsSet);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Missing JWT expiration (exp) claim", e.getMessage());
		}
	}


	public void testMissingIssueTime() {

		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, null, 0);

		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		assertNull(verifier.getExpectedNonce());

		Date now = new Date();
		Date exp = new Date(now.getTime() + 5*60*1000);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.subject("alice")
			.audience(clientID.getValue())
			.expirationTime(exp)
			.build();

		try {
			verifier.verify(claimsSet);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Missing JWT issue time (iat) claim", e.getMessage());
		}
	}


	public void testMissingNonce() {

		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Nonce nonce = new Nonce("xyz");

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, nonce, 0);

		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		assertEquals(nonce, verifier.getExpectedNonce());

		Date now = new Date();
		Date iat = new Date(now.getTime() - 5*60*1000);
		Date exp = new Date(now.getTime() + 5*60*1000);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.subject("alice")
			.audience(clientID.getValue())
			.expirationTime(exp)
			.issueTime(iat)
			.build();

		try {
			verifier.verify(claimsSet);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Missing JWT nonce (nonce) claim", e.getMessage());
		}
	}


	public void testUnexpectedIssuer() {

		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Nonce nonce = new Nonce("xyz");

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, nonce, 0);

		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		assertEquals(nonce, verifier.getExpectedNonce());

		Date now = new Date();
		Date iat = new Date(now.getTime() - 5*60*1000);
		Date exp = new Date(now.getTime() + 5*60*1000);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer("https://other-issuer.com")
			.subject("alice")
			.audience(clientID.getValue())
			.expirationTime(exp)
			.issueTime(iat)
			.claim("nonce", nonce.getValue())
			.build();

		try {
			verifier.verify(claimsSet);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Unexpected JWT issuer: https://other-issuer.com", e.getMessage());
		}
	}


	public void testAudienceMismatch() {

		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Nonce nonce = new Nonce("xyz");

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, nonce, 0);

		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		assertEquals(nonce, verifier.getExpectedNonce());

		Date now = new Date();
		Date iat = new Date(now.getTime() - 5*60*1000);
		Date exp = new Date(now.getTime() + 5*60*1000);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.subject("alice")
			.audience("789")
			.expirationTime(exp)
			.issueTime(iat)
			.claim("nonce", nonce.getValue())
			.build();

		try {
			verifier.verify(claimsSet);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Unexpected JWT audience: [789]", e.getMessage());
		}
	}


	public void testMultipleAudienceMismatch() {

		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Nonce nonce = new Nonce("xyz");

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, nonce, 0);

		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		assertEquals(nonce, verifier.getExpectedNonce());

		Date now = new Date();
		Date iat = new Date(now.getTime() - 5*60*1000);
		Date exp = new Date(now.getTime() + 5*60*1000);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.subject("alice")
			.audience(Arrays.asList("456", "789"))
			.expirationTime(exp)
			.issueTime(iat)
			.claim("nonce", nonce.getValue())
			.build();

		try {
			verifier.verify(claimsSet);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Unexpected JWT audience: [456, 789]", e.getMessage());
		}
	}


	public void testAzpMismatch() {

		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Nonce nonce = new Nonce("xyz");

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, nonce, 0);

		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		assertEquals(nonce, verifier.getExpectedNonce());

		Date now = new Date();
		Date iat = new Date(now.getTime() - 5*60*1000);
		Date exp = new Date(now.getTime() + 5*60*1000);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.subject("alice")
			.audience(Arrays.asList(clientID.getValue(), "456"))
			.claim("azp", "456")
			.expirationTime(exp)
			.issueTime(iat)
			.claim("nonce", nonce.getValue())
			.build();

		try {
			verifier.verify(claimsSet);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Unexpected JWT authorized party (azp) claim: 456", e.getMessage());
		}
	}


	public void testExpired() {

		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Nonce nonce = new Nonce("xyz");

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, nonce, 0);

		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		assertEquals(nonce, verifier.getExpectedNonce());

		final Date now = new Date();
		final Date oneHourAgo = new Date(now.getTime() - 60*60*1000L);
		final Date twoHoursAgo = new Date(now.getTime() - 2*60*60*1000L);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.subject("alice")
			.audience(clientID.getValue())
			.expirationTime(oneHourAgo)
			.issueTime(twoHoursAgo)
			.claim("nonce", nonce.getValue())
			.build();

		try {
			verifier.verify(claimsSet);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Expired JWT", e.getMessage());
		}
	}


	public void testIssueTimeAhead() {

		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Nonce nonce = new Nonce("xyz");

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, nonce, 0);

		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		assertEquals(nonce, verifier.getExpectedNonce());

		final Date now = new Date();
		final Date inOneHour = new Date(now.getTime() + 60*60*1000L);
		final Date inTwoHours = new Date(now.getTime() + 2*60*60*1000L);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.subject("alice")
			.audience(clientID.getValue())
			.expirationTime(inTwoHours)
			.issueTime(inOneHour)
			.claim("nonce", nonce.getValue())
			.build();

		try {
			verifier.verify(claimsSet);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT issue time ahead of current time", e.getMessage());
		}
	}


	public void testUnexpectedNonce() {

		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Nonce nonce = new Nonce("xyz");

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, nonce, 0);

		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		assertEquals(nonce, verifier.getExpectedNonce());

		Date now = new Date();
		Date iat = new Date(now.getTime() - 5*60*1000);
		Date exp = new Date(now.getTime() + 5*60*1000);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.subject("alice")
			.audience(clientID.getValue())
			.expirationTime(exp)
			.issueTime(iat)
			.claim("nonce", "xxx")
			.build();

		try {
			verifier.verify(claimsSet);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Unexpected JWT nonce (nonce) claim: xxx", e.getMessage());
		}
	}


	public void testIssuedAtWithPositiveClockSkew()
		throws BadJWTException {

		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Nonce nonce = new Nonce("xyz");

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, nonce, 60);

		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		assertEquals(nonce, verifier.getExpectedNonce());

		final Date now = new Date();
		final Date in30Seconds = new Date(now.getTime() + 30*1000L);
		final Date inOneHour = new Date(now.getTime() + 60*60*1000L);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
				.issuer(iss.getValue())
				.subject("alice")
				.audience(clientID.getValue())
				.expirationTime(inOneHour)
				.issueTime(in30Seconds)
				.claim("nonce", nonce.getValue())
				.build();

		verifier.verify(claimsSet);
	}


	public void testExpirationWithNegativeClockSkew()
		throws BadJWTException {

		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Nonce nonce = new Nonce("xyz");

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, nonce, 60);

		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		assertEquals(nonce, verifier.getExpectedNonce());

		final Date now = new Date();
		final Date oneHourAgo = new Date(now.getTime() - 60*60*1000L);
		final Date before30Seconds = new Date(now.getTime() - 30*1000L);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
				.issuer(iss.getValue())
				.subject("alice")
				.audience(clientID.getValue())
				.expirationTime(before30Seconds)
				.issueTime(oneHourAgo)
				.claim("nonce", nonce.getValue())
				.build();

		verifier.verify(claimsSet);
	}
}

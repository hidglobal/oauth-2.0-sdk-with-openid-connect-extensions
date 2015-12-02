package com.nimbusds.openid.connect.sdk.token.verifiers;


import java.util.Arrays;
import java.util.Date;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.util.DateUtils;
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

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, nonce);

		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		assertEquals(nonce, verifier.getExpectedNonce());

		final Date now = new Date();
		final Date inOneHour = new Date(now.getTime() + 60*60*1000L);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.subject("alice")
			.audience(clientID.getValue())
			.expirationTime(inOneHour)
			.issueTime(now)
			.claim("nonce", nonce.getValue())
			.build();

		verifier.verify(claimsSet);
	}


	public void testHappyMinimalWithoutNonce()
		throws BadJWTException {

		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, null);

		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		assertNull(verifier.getExpectedNonce());

		final Date now = new Date();
		final Date inOneHour = new Date(now.getTime() + 60*60*1000L);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.subject("alice")
			.audience(clientID.getValue())
			.expirationTime(inOneHour)
			.issueTime(now)
			.build();

		verifier.verify(claimsSet);
	}


	public void testMissingIssuer() {

		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, null);

		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		assertNull(verifier.getExpectedNonce());

		final Date now = new Date();
		final Date inOneHour = new Date(now.getTime() + 60*60*1000L);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.audience(clientID.getValue())
			.expirationTime(inOneHour)
			.issueTime(now)
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

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, null);

		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		assertNull(verifier.getExpectedNonce());

		final Date now = new Date();
		final Date inOneHour = new Date(now.getTime() + 60*60*1000L);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.audience(clientID.getValue())
			.expirationTime(inOneHour)
			.issueTime(now)
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

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, null);

		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		assertNull(verifier.getExpectedNonce());

		final Date now = new Date();
		final Date inOneHour = new Date(now.getTime() + 60*60*1000L);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.subject("alice")
			.expirationTime(inOneHour)
			.issueTime(now)
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

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, null);

		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		assertNull(verifier.getExpectedNonce());

		final Date now = new Date();

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.subject("alice")
			.audience(clientID.getValue())
			.issueTime(now)
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

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, null);

		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		assertNull(verifier.getExpectedNonce());

		final Date now = new Date();
		final Date inOneHour = new Date(now.getTime() + 60*60*1000L);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.subject("alice")
			.audience(clientID.getValue())
			.expirationTime(inOneHour)
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

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, nonce);

		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		assertEquals(nonce, verifier.getExpectedNonce());

		final Date now = DateUtils.fromSecondsSinceEpoch(1000);
		final Date exp = DateUtils.fromSecondsSinceEpoch(1001);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.subject("alice")
			.audience(clientID.getValue())
			.expirationTime(exp)
			.issueTime(now)
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

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, nonce);

		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		assertEquals(nonce, verifier.getExpectedNonce());

		final Date now = new Date();
		final Date inOneHour = new Date(now.getTime() + 60*60*1000L);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer("https://other-issuer.com")
			.subject("alice")
			.audience(clientID.getValue())
			.expirationTime(inOneHour)
			.issueTime(now)
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

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, nonce);

		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		assertEquals(nonce, verifier.getExpectedNonce());

		final Date now = new Date();
		final Date inOneHour = new Date(now.getTime() + 60*60*1000L);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.subject("alice")
			.audience("789")
			.expirationTime(inOneHour)
			.issueTime(now)
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

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, nonce);

		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		assertEquals(nonce, verifier.getExpectedNonce());

		final Date now = new Date();
		final Date inOneHour = new Date(now.getTime() + 60*60*1000L);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.subject("alice")
			.audience(Arrays.asList("456", "789"))
			.expirationTime(inOneHour)
			.issueTime(now)
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

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, nonce);

		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		assertEquals(nonce, verifier.getExpectedNonce());

		final Date now = new Date();
		final Date inOneHour = new Date(now.getTime() + 60*60*1000L);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.subject("alice")
			.audience(Arrays.asList(clientID.getValue(), "456"))
			.claim("azp", "456")
			.expirationTime(inOneHour)
			.issueTime(now)
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

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, nonce);

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


	public void testAcceptIssueTimeAhead() {

		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Nonce nonce = new Nonce("xyz");

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, nonce);

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

		IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, nonce);

		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		assertEquals(nonce, verifier.getExpectedNonce());

		final Date now = new Date();
		final Date inOneHour = new Date(now.getTime() + 60*60*1000L);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.subject("alice")
			.audience(clientID.getValue())
			.expirationTime(inOneHour)
			.issueTime(now)
			.claim("nonce", "xxx")
			.build();

		try {
			verifier.verify(claimsSet);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Unexpected JWT nonce (nonce) claim: xxx", e.getMessage());
		}
	}
}

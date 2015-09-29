package com.nimbusds.oauth2.sdk.auth;


import java.util.Date;
import java.util.List;

import junit.framework.TestCase;

import net.minidev.json.JSONObject;

import com.nimbusds.jwt.JWTClaimsSet;

import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * Tests the client_secret_jwt and private_key_jwt claims set.
 */
public class JWTAuthenticationClaimsSetTest extends TestCase {


	public void testReservedClaimsNames() {

		// http://tools.ietf.org/html/rfc7523#section-3
		assertTrue(JWTAuthenticationClaimsSet.getReservedClaimsNames().contains("iss"));
		assertTrue(JWTAuthenticationClaimsSet.getReservedClaimsNames().contains("sub"));
		assertTrue(JWTAuthenticationClaimsSet.getReservedClaimsNames().contains("aud"));
		assertTrue(JWTAuthenticationClaimsSet.getReservedClaimsNames().contains("exp"));
		assertTrue(JWTAuthenticationClaimsSet.getReservedClaimsNames().contains("nbf"));
		assertTrue(JWTAuthenticationClaimsSet.getReservedClaimsNames().contains("iat"));
		assertTrue(JWTAuthenticationClaimsSet.getReservedClaimsNames().contains("jti"));
		assertEquals(7, JWTAuthenticationClaimsSet.getReservedClaimsNames().size());
	}


	public void testMinimalConstructor()
		throws Exception {

		ClientID clientID = new ClientID("123");
		Audience aud = new Audience("https://c2id.com/token");

		JWTAuthenticationClaimsSet claimsSet = new JWTAuthenticationClaimsSet(clientID, aud);

		// Test getters
		assertEquals(clientID, claimsSet.getClientID());
		assertEquals(clientID.getValue(), claimsSet.getIssuer().getValue());
		assertEquals(clientID.getValue(), claimsSet.getSubject().getValue());
		assertEquals(aud, claimsSet.getAudience());

		// 4 min < exp < 6 min
		final long now = new Date().getTime();
		final Date fourMinutesFromNow = new Date(now + 4*60*1000l);
		final Date sixMinutesFromNow = new Date(now + 6*60*1000l);
		assertTrue(claimsSet.getExpirationTime().after(fourMinutesFromNow));
		assertTrue(claimsSet.getExpirationTime().before(sixMinutesFromNow));

		assertNull(claimsSet.getIssueTime());
		assertNull(claimsSet.getNotBeforeTime());

		assertNotNull(claimsSet.getJWTID());
		assertEquals(new JWTID().getValue().length(), claimsSet.getJWTID().getValue().length());

		// Test output to JSON object
		JSONObject jsonObject = claimsSet.toJSONObject();
		assertEquals("123", jsonObject.get("iss"));
		assertEquals("123", jsonObject.get("sub"));
		List<String> audList = JSONObjectUtils.getStringList(jsonObject, "aud");
		assertEquals("https://c2id.com/token", audList.get(0));
		assertEquals(1, audList.size());
		assertEquals(claimsSet.getExpirationTime().getTime() / 1000l, JSONObjectUtils.getLong(jsonObject, "exp"));
		assertEquals(claimsSet.getJWTID().getValue(), jsonObject.get("jti"));
		assertEquals(5, jsonObject.size());

		// Test output to JWT claims set
		JWTClaimsSet jwtClaimsSet = claimsSet.toJWTClaimsSet();
		assertEquals("123", jwtClaimsSet.getIssuer());
		assertEquals("123", jwtClaimsSet.getSubject());
		assertEquals("https://c2id.com/token", jwtClaimsSet.getAudience().get(0));
		assertEquals(1, jwtClaimsSet.getAudience().size());
		assertEquals(claimsSet.getExpirationTime().getTime() / 1000l, jwtClaimsSet.getExpirationTime().getTime() / 1000);
		assertEquals(claimsSet.getJWTID().getValue(), jwtClaimsSet.getJWTID());
		assertEquals(5, jwtClaimsSet.toJSONObject().size());

		// Test parse
		JWTAuthenticationClaimsSet parsed = JWTAuthenticationClaimsSet.parse(jwtClaimsSet);
		assertEquals(clientID, parsed.getClientID());
		assertEquals(clientID.getValue(), parsed.getIssuer().getValue());
		assertEquals(clientID.getValue(), parsed.getSubject().getValue());
		assertEquals(claimsSet.getAudience(), parsed.getAudience());
		assertEquals(claimsSet.getExpirationTime().getTime() / 1000l, parsed.getExpirationTime().getTime() / 1000l);
		assertNull(parsed.getIssueTime());
		assertNull(parsed.getNotBeforeTime());
		assertEquals(claimsSet.getJWTID(), parsed.getJWTID());
	}


	public void testNullJTI() {

		final long now = new Date().getTime();
		final Date fiveMinutesFromNow = new Date(now + 5*60*1000l);

		JWTAuthenticationClaimsSet claimsSet = new JWTAuthenticationClaimsSet(
			new ClientID("123"),
			new Audience("https://c2id.com/token"),
			fiveMinutesFromNow,
			null, // nbf
			null, // iat
			null); // jti

		JWTClaimsSet jwtClaimsSet = claimsSet.toJWTClaimsSet();
		assertNull(jwtClaimsSet.getJWTID());
	}
}

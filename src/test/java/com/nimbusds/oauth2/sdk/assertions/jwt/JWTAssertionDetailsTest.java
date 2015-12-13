package com.nimbusds.oauth2.sdk.assertions.jwt;


import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import junit.framework.TestCase;
import net.minidev.json.JSONObject;


/**
 * Tests the JWT bearer assertion details (claims set).
 */
public class JWTAssertionDetailsTest extends TestCase {


	public void testReservedClaimsNames() {

		// http://tools.ietf.org/html/rfc7523#section-3
		assertTrue(JWTAssertionDetails.getReservedClaimsNames().contains("iss"));
		assertTrue(JWTAssertionDetails.getReservedClaimsNames().contains("sub"));
		assertTrue(JWTAssertionDetails.getReservedClaimsNames().contains("aud"));
		assertTrue(JWTAssertionDetails.getReservedClaimsNames().contains("exp"));
		assertTrue(JWTAssertionDetails.getReservedClaimsNames().contains("nbf"));
		assertTrue(JWTAssertionDetails.getReservedClaimsNames().contains("iat"));
		assertTrue(JWTAssertionDetails.getReservedClaimsNames().contains("jti"));
		assertEquals(7, JWTAssertionDetails.getReservedClaimsNames().size());
	}


	public void testMinimalConstructor()
		throws Exception {

		Issuer iss = new Issuer("http://example.com");
		Subject sub = new Subject("alice");
		Audience aud = new Audience("https://c2id.com/token");

		JWTAssertionDetails claimsSet = new JWTAssertionDetails(iss, sub, aud);

		// Test getters
		assertEquals(iss, claimsSet.getIssuer());
		assertEquals(sub, claimsSet.getSubject());
		assertEquals(aud, claimsSet.getAudience().get(0));

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

		assertNull(claimsSet.getCustomClaims());

		// Test output to JSON object
		JSONObject jsonObject = claimsSet.toJSONObject();
		assertEquals("http://example.com", jsonObject.get("iss"));
		assertEquals("alice", jsonObject.get("sub"));
		List<String> audList = JSONObjectUtils.getStringList(jsonObject, "aud");
		assertEquals("https://c2id.com/token", audList.get(0));
		assertEquals(1, audList.size());
		assertEquals(claimsSet.getExpirationTime().getTime() / 1000l, JSONObjectUtils.getLong(jsonObject, "exp"));
		assertEquals(claimsSet.getJWTID().getValue(), jsonObject.get("jti"));
		assertEquals(5, jsonObject.size());

		// Test output to JWT claims set
		JWTClaimsSet jwtClaimsSet = claimsSet.toJWTClaimsSet();
		assertEquals("http://example.com", jwtClaimsSet.getIssuer());
		assertEquals("alice", jwtClaimsSet.getSubject());
		assertEquals("https://c2id.com/token", jwtClaimsSet.getAudience().get(0));
		assertEquals(1, jwtClaimsSet.getAudience().size());
		assertEquals(claimsSet.getExpirationTime().getTime() / 1000l, jwtClaimsSet.getExpirationTime().getTime() / 1000);
		assertEquals(claimsSet.getJWTID().getValue(), jwtClaimsSet.getJWTID());
		assertEquals(5, jwtClaimsSet.toJSONObject().size());

		// Test parse
		JWTAssertionDetails parsed = JWTAssertionDetails.parse(jwtClaimsSet);
		assertEquals(iss, parsed.getIssuer());
		assertEquals(sub, parsed.getSubject());
		assertEquals(aud, parsed.getAudience().get(0));
		assertEquals(claimsSet.getExpirationTime().getTime() / 1000l, parsed.getExpirationTime().getTime() / 1000l);
		assertNull(parsed.getIssueTime());
		assertNull(parsed.getNotBeforeTime());
		assertEquals(claimsSet.getJWTID(), parsed.getJWTID());
		assertNull(claimsSet.getCustomClaims());
	}


	public void testWithOtherClaims()
		throws Exception {

		Map<String,Object> other = new LinkedHashMap<>();
		other.put("A", "B");
		other.put("ten", 10l);

		JWTAssertionDetails claimsSet = new JWTAssertionDetails(
			new Issuer("123"),
			new Subject("alice"),
			new Audience("https://c2id.com/token").toSingleAudienceList(),
			new Date(),
			null,
			null,
			null,
			other);

		assertEquals(other, claimsSet.getCustomClaims());

		// Test output to JSON object
		JSONObject jsonObject = claimsSet.toJSONObject();

		assertEquals("123", jsonObject.get("iss"));
		assertEquals("alice", jsonObject.get("sub"));
		assertEquals("https://c2id.com/token", JSONObjectUtils.getStringList(jsonObject, "aud").get(0));
		assertEquals(1, JSONObjectUtils.getStringList(jsonObject, "aud").size());
		assertNotNull(jsonObject.get("exp"));
		assertEquals("B", jsonObject.get("A"));
		assertEquals(10l, jsonObject.get("ten"));
		assertEquals(6, jsonObject.size());

		// Test output to JWT claims set
		JWTClaimsSet jwtClaimsSet = claimsSet.toJWTClaimsSet();
		assertEquals("123", jwtClaimsSet.getIssuer());
		assertEquals("alice", jwtClaimsSet.getSubject());
		assertEquals("https://c2id.com/token", jwtClaimsSet.getAudience().get(0));
		assertEquals(1, jwtClaimsSet.getAudience().size());
		assertNotNull(jwtClaimsSet.getExpirationTime());
		assertEquals("B", jwtClaimsSet.getStringClaim("A"));
		assertEquals(10l, jwtClaimsSet.getLongClaim("ten").longValue());

		// Test parse
		JWTAssertionDetails parsed = JWTAssertionDetails.parse(jwtClaimsSet);
		assertEquals("123", parsed.getIssuer().getValue());
		assertEquals("alice", parsed.getSubject().getValue());
		assertEquals("https://c2id.com/token", parsed.getAudience().get(0).getValue());
		assertEquals(claimsSet.getExpirationTime().getTime() / 1000l, parsed.getExpirationTime().getTime() / 1000l);
		assertNull(parsed.getIssueTime());
		assertNull(parsed.getNotBeforeTime());
		assertEquals(claimsSet.getJWTID(), parsed.getJWTID());
		assertNotNull(claimsSet.getCustomClaims());
		other = claimsSet.getCustomClaims();
		assertEquals("B", other.get("A"));
		assertEquals(10l, other.get("ten"));
		assertEquals(2, other.size());
	}
}

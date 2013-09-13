package com.nimbusds.openid.connect.sdk.claims;


import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.util.DateUtils;
import junit.framework.TestCase;


/**
 * Tests the ID token claims set.
 *
 * @author Vladimir Dzhuvinov
 */
public class IDTokenClaimsSetTest extends TestCase {


	public void testParseRoundTrip()
		throws Exception {

		// Example from messages spec

		String json = "{\n" +
			"   \"iss\"       : \"https://server.example.com\",\n" +
			"   \"sub\"       : \"24400320\",\n" +
			"   \"aud\"       : \"s6BhdRkqt3\",\n" +
			"   \"nonce\"     : \"n-0S6_WzA2Mj\",\n" +
			"   \"exp\"       : 1311281970,\n" +
			"   \"iat\"       : 1311280970,\n" +
			"   \"auth_time\" : 1311280969,\n" +
			"   \"acr\"       : \"urn:mace:incommon:iap:silver\",\n" +
			"   \"at_hash\"   : \"MTIzNDU2Nzg5MDEyMzQ1Ng\"\n" +
			" }";

		JWTClaimsSet jwtClaimsSet = JWTClaimsSet.parse(json);

		IDTokenClaimsSet idTokenClaimsSet = new IDTokenClaimsSet(jwtClaimsSet);

		assertEquals("https://server.example.com", idTokenClaimsSet.getIssuer().getValue());
		assertEquals("24400320", idTokenClaimsSet.getSubject().getValue());
		assertEquals("s6BhdRkqt3", idTokenClaimsSet.getAudience().get(0).getValue());
		assertEquals("n-0S6_WzA2Mj", idTokenClaimsSet.getNonce().getValue());
		assertEquals(1311281970l, DateUtils.toSecondsSinceEpoch(idTokenClaimsSet.getExpirationTime()));
		assertEquals(1311280970l, DateUtils.toSecondsSinceEpoch(idTokenClaimsSet.getIssueTime()));
		assertEquals(1311280969l, DateUtils.toSecondsSinceEpoch(idTokenClaimsSet.getAuthenticationTime()));
		assertEquals("urn:mace:incommon:iap:silver", idTokenClaimsSet.getACR().getValue());
		assertEquals("MTIzNDU2Nzg5MDEyMzQ1Ng", idTokenClaimsSet.getAccessTokenHash().getValue());

		json = idTokenClaimsSet.toJWTClaimsSet().toJSONObject().toJSONString();

		jwtClaimsSet = JWTClaimsSet.parse(json);

		idTokenClaimsSet = new IDTokenClaimsSet(jwtClaimsSet);

		assertEquals("https://server.example.com", idTokenClaimsSet.getIssuer().getValue());
		assertEquals("24400320", idTokenClaimsSet.getSubject().getValue());
		assertEquals("s6BhdRkqt3", idTokenClaimsSet.getAudience().get(0).getValue());
		assertEquals("n-0S6_WzA2Mj", idTokenClaimsSet.getNonce().getValue());
		assertEquals(1311281970l, DateUtils.toSecondsSinceEpoch(idTokenClaimsSet.getExpirationTime()));
		assertEquals(1311280970l, DateUtils.toSecondsSinceEpoch(idTokenClaimsSet.getIssueTime()));
		assertEquals(1311280969l, DateUtils.toSecondsSinceEpoch(idTokenClaimsSet.getAuthenticationTime()));
		assertEquals("urn:mace:incommon:iap:silver", idTokenClaimsSet.getACR().getValue());
		assertEquals("MTIzNDU2Nzg5MDEyMzQ1Ng", idTokenClaimsSet.getAccessTokenHash().getValue());
	}

}

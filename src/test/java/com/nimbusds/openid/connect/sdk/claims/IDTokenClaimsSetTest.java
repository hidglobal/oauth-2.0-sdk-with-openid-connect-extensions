package com.nimbusds.openid.connect.sdk.claims;


import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import junit.framework.TestCase;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.DateUtils;

import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;


/**
 * Tests the ID token claims set.
 */
public class IDTokenClaimsSetTest extends TestCase {


	public void testClaimNameConstants() {

		assertEquals("acr", IDTokenClaimsSet.ACR_CLAIM_NAME);
		assertEquals("amr", IDTokenClaimsSet.AMR_CLAIM_NAME);
		assertEquals("at_hash", IDTokenClaimsSet.AT_HASH_CLAIM_NAME);
		assertEquals("aud", IDTokenClaimsSet.AUD_CLAIM_NAME);
		assertEquals("auth_time", IDTokenClaimsSet.AUTH_TIME_CLAIM_NAME);
		assertEquals("azp", IDTokenClaimsSet.AZP_CLAIM_NAME);
		assertEquals("c_hash", IDTokenClaimsSet.C_HASH_CLAIM_NAME);
		assertEquals("exp", IDTokenClaimsSet.EXP_CLAIM_NAME);
		assertEquals("iat", IDTokenClaimsSet.IAT_CLAIM_NAME);
		assertEquals("iss", IDTokenClaimsSet.ISS_CLAIM_NAME);
		assertEquals("nonce", IDTokenClaimsSet.NONCE_CLAIM_NAME);
		assertEquals("sub", IDTokenClaimsSet.SUB_CLAIM_NAME);
		assertEquals("sub_jwk", IDTokenClaimsSet.SUB_JWK_CLAIM_NAME);
	}


	public void testStdClaims() {

		Set<String> stdClaimNames = IDTokenClaimsSet.getStandardClaimNames();

		assertTrue(stdClaimNames.contains("iss"));
		assertTrue(stdClaimNames.contains("sub"));
		assertTrue(stdClaimNames.contains("aud"));
		assertTrue(stdClaimNames.contains("exp"));
		assertTrue(stdClaimNames.contains("iat"));
		assertTrue(stdClaimNames.contains("auth_time"));
		assertTrue(stdClaimNames.contains("nonce"));
		assertTrue(stdClaimNames.contains("at_hash"));
		assertTrue(stdClaimNames.contains("c_hash"));
		assertTrue(stdClaimNames.contains("acr"));
		assertTrue(stdClaimNames.contains("amr"));
		assertTrue(stdClaimNames.contains("azp"));
		assertTrue(stdClaimNames.contains("sub_jwk"));

		assertEquals(13, stdClaimNames.size());
	}


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


	public void testGettersAndSetters()
		throws Exception {

		Issuer issuer = new Issuer("iss");
		Subject subject = new Subject("sub");

		List<Audience> audList = new LinkedList<Audience>();
		audList.add(new Audience("aud"));

		Date expirationTime = DateUtils.fromSecondsSinceEpoch(100000l);
		Date issueTime = DateUtils.fromSecondsSinceEpoch(200000l);

		IDTokenClaimsSet idTokenClaimsSet = new IDTokenClaimsSet(issuer, subject, audList, expirationTime, issueTime);

		Date authenticationTime = DateUtils.fromSecondsSinceEpoch(300000l);
		idTokenClaimsSet.setAuthenticationTime(authenticationTime);

		Nonce nonce = new Nonce();
		idTokenClaimsSet.setNonce(nonce);

		AccessTokenHash accessTokenHash = new AccessTokenHash("123");
		idTokenClaimsSet.setAccessTokenHash(accessTokenHash);

		CodeHash codeHash = new CodeHash("456");
		idTokenClaimsSet.setCodeHash(codeHash);

		ACR acr = new ACR("1");
		idTokenClaimsSet.setACR(acr);

		List<AMR> amrList = new LinkedList<AMR>();
		amrList.add(new AMR("A"));
		idTokenClaimsSet.setAMR(amrList);

		AuthorizedParty authorizedParty = new AuthorizedParty("azp");
		idTokenClaimsSet.setAuthorizedParty(authorizedParty);

		// Mandatory claims
		assertEquals("iss", idTokenClaimsSet.getIssuer().getValue());
		assertEquals("sub", idTokenClaimsSet.getSubject().getValue());
		assertEquals("aud", idTokenClaimsSet.getAudience().get(0).getValue());
		assertEquals(100000l, idTokenClaimsSet.getExpirationTime().getTime() / 1000);
		assertEquals(200000l, idTokenClaimsSet.getIssueTime().getTime() / 1000);

		// Optional claims
		assertEquals(300000l, idTokenClaimsSet.getAuthenticationTime().getTime() / 1000);
		assertEquals(nonce.getValue(), idTokenClaimsSet.getNonce().getValue());
		assertEquals(accessTokenHash.getValue(), idTokenClaimsSet.getAccessTokenHash().getValue());
		assertEquals(codeHash.getValue(), idTokenClaimsSet.getCodeHash().getValue());
		assertEquals(acr.getValue(), idTokenClaimsSet.getACR().getValue());
		assertEquals("A", idTokenClaimsSet.getAMR().get(0).getValue());
		assertEquals(authorizedParty.getValue(), idTokenClaimsSet.getAuthorizedParty().getValue());

		String json = idTokenClaimsSet.toJSONObject().toJSONString();

		// Try to JWT claims set too
		idTokenClaimsSet.toJWTClaimsSet();

		idTokenClaimsSet = IDTokenClaimsSet.parse(json);

		// Mandatory claims
		assertEquals("iss", idTokenClaimsSet.getIssuer().getValue());
		assertEquals("sub", idTokenClaimsSet.getSubject().getValue());
		assertEquals("aud", idTokenClaimsSet.getAudience().get(0).getValue());
		assertEquals(100000l, idTokenClaimsSet.getExpirationTime().getTime() / 1000);
		assertEquals(200000l, idTokenClaimsSet.getIssueTime().getTime() / 1000);

		// Optional claims
		assertEquals(300000l, idTokenClaimsSet.getAuthenticationTime().getTime() / 1000);
		assertEquals(nonce.getValue(), idTokenClaimsSet.getNonce().getValue());
		assertEquals(accessTokenHash.getValue(), idTokenClaimsSet.getAccessTokenHash().getValue());
		assertEquals(codeHash.getValue(), idTokenClaimsSet.getCodeHash().getValue());
		assertEquals(acr.getValue(), idTokenClaimsSet.getACR().getValue());
		assertEquals("A", idTokenClaimsSet.getAMR().get(0).getValue());
		assertEquals(authorizedParty.getValue(), idTokenClaimsSet.getAuthorizedParty().getValue());
	}


	public void testSingleAudSetAndGetWorkaround()
		throws Exception {

		Issuer issuer = new Issuer("iss");
		Subject subject = new Subject("sub");

		List<Audience> audList = new LinkedList<Audience>();
		audList.add(new Audience("aud"));

		Date expirationTime = DateUtils.fromSecondsSinceEpoch(100000l);
		Date issueTime = DateUtils.fromSecondsSinceEpoch(200000l);

		IDTokenClaimsSet idTokenClaimsSet = new IDTokenClaimsSet(issuer, subject, audList, expirationTime, issueTime);

		idTokenClaimsSet.setClaim("aud", "client-1");

		assertEquals("client-1", idTokenClaimsSet.getAudience().get(0).getValue());
	}


	public void testHasRequiredClaimsImplicitFlow() {

		ResponseType responseType = new ResponseType();
		responseType.add(ResponseType.Value.TOKEN);
		responseType.add(OIDCResponseTypeValue.ID_TOKEN);

		IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(
			new Issuer("iss"),
			new Subject("sub"),
			new Audience("aud").toSingleAudienceList(),
			new Date(),
			new Date());

		assertFalse(claimsSet.hasRequiredClaims(responseType));

		claimsSet.setNonce(new Nonce());
		claimsSet.setAccessTokenHash(new AccessTokenHash("at_hash"));

		assertTrue(claimsSet.hasRequiredClaims(responseType));
	}


	public void testHasRequiredClaimsCodeFlow() {

		ResponseType responseType = new ResponseType();
		responseType.add(ResponseType.Value.CODE);

		IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(
			new Issuer("iss"),
			new Subject("sub"),
			new Audience("aud").toSingleAudienceList(),
			new Date(),
			new Date());

		assertFalse(claimsSet.hasRequiredClaims(responseType));

		claimsSet.setCodeHash(new CodeHash("c_hash"));

		assertTrue(claimsSet.hasRequiredClaims(responseType));
	}


	public void testHasRequiredClaimsHybridFlow() {

		ResponseType responseType = new ResponseType();
		responseType.add(ResponseType.Value.CODE);
		responseType.add(ResponseType.Value.TOKEN);
		responseType.add(OIDCResponseTypeValue.ID_TOKEN);

		IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(
			new Issuer("iss"),
			new Subject("sub"),
			new Audience("aud").toSingleAudienceList(),
			new Date(),
			new Date());

		assertFalse(claimsSet.hasRequiredClaims(responseType));

		claimsSet.setCodeHash(new CodeHash("c_hash"));

		claimsSet.setNonce(new Nonce());
		claimsSet.setAccessTokenHash(new AccessTokenHash("at_hash"));

		assertTrue(claimsSet.hasRequiredClaims(responseType));
	}


	public void testSubjectJWK()
		throws Exception {

		IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(
			new Issuer("iss"),
			new Subject("sub"),
			new Audience("aud").toSingleAudienceList(),
			new Date(),
			new Date());

		assertNull(claimsSet.getSubjectJWK());

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(512);

		KeyPair keyPair = keyGen.generateKeyPair();

		RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic();

		RSAKey rsaJWK = new RSAKey.Builder(publicKey).keyID("1").build();

		claimsSet.setSubjectJWK(rsaJWK);

		RSAKey rsaJWKOut = (RSAKey)claimsSet.getSubjectJWK();

		assertEquals(rsaJWK.getModulus(), rsaJWKOut.getModulus());
		assertEquals(rsaJWK.getPublicExponent(), rsaJWKOut.getPublicExponent());
		assertEquals(rsaJWK.getKeyID(), rsaJWKOut.getKeyID());


		String json = claimsSet.toJSONObject().toJSONString();

		System.out.println("ID token with subject JWK: " + json);

		claimsSet = IDTokenClaimsSet.parse(json);

		rsaJWKOut = (RSAKey)claimsSet.getSubjectJWK();

		assertEquals(rsaJWK.getModulus(), rsaJWKOut.getModulus());
		assertEquals(rsaJWK.getPublicExponent(), rsaJWKOut.getPublicExponent());
		assertEquals(rsaJWK.getKeyID(), rsaJWKOut.getKeyID());
	}


	public void testRejectPrivateSubjectJWK()
		throws Exception {

		IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(
			new Issuer("iss"),
			new Subject("sub"),
			new Audience("aud").toSingleAudienceList(),
			new Date(),
			new Date());

		assertNull(claimsSet.getSubjectJWK());

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(512);

		KeyPair keyPair = keyGen.generateKeyPair();

		RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPrivate();

		RSAKey rsaJWK = new RSAKey.Builder(publicKey).privateKey(privateKey).build();

		try {
			claimsSet.setSubjectJWK(rsaJWK);

			fail();

		} catch (IllegalArgumentException e) {
			// ok
		}
	}
}

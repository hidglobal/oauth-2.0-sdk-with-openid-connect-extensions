package com.nimbusds.oauth2.sdk.auth;


import java.net.URI;
import java.util.*;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.*;

import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.util.DateUtils;

import junit.framework.TestCase;


/**
 * Tests the client secret JWT authentication class.
 */
public class ClientSecretJWTTest extends TestCase {


	public void testSupportedJWAs() {

		Set<JWSAlgorithm> algs = ClientSecretJWT.supportedJWAs();

		assertTrue(algs.contains(JWSAlgorithm.HS256));
		assertTrue(algs.contains(JWSAlgorithm.HS384));
		assertTrue(algs.contains(JWSAlgorithm.HS512));
		assertEquals(3, algs.size());
	}


	public void testRun()
		throws Exception {

		ClientID clientID = new ClientID("http://client.com");
		Audience audience = new Audience("http://idp.com");
		Date exp = DateUtils.fromSecondsSinceEpoch(new Date().getTime() / 1000 + 3600);
		Date nbf = DateUtils.fromSecondsSinceEpoch(new Date().getTime() / 1000);
		Date iat = DateUtils.fromSecondsSinceEpoch(new Date().getTime() / 1000);
		JWTID jti = new JWTID();

		JWTAuthenticationClaimsSet assertion = new JWTAuthenticationClaimsSet(clientID, audience.toSingleAudienceList(), exp, nbf, iat, jti);

		System.out.println("Client secret JWT claims set: " + assertion.toJSONObject());


		JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.HS256);

		SignedJWT jwt = new SignedJWT(jwsHeader, assertion.toJWTClaimsSet());

		Secret secret = new Secret();

		MACSigner signer = new MACSigner(secret.getValueBytes());

		jwt.sign(signer);

		ClientSecretJWT clientSecretJWT = new ClientSecretJWT(jwt);

		Map<String,String> params = clientSecretJWT.toParameters();
		params.put("client_id", clientID.getValue()); // add optional client_id to test parser

		System.out.println("Client secret JWT: " + params);

		clientSecretJWT = ClientSecretJWT.parse(params);

		assertEquals("http://client.com", clientSecretJWT.getClientID().getValue());

		jwt = clientSecretJWT.getClientAssertion();

		assertTrue(jwt.getState().equals(JWSObject.State.SIGNED));

		MACVerifier verifier = new MACVerifier(secret.getValueBytes());

		boolean verified = jwt.verify(verifier);

		assertTrue(verified);

		assertion = clientSecretJWT.getJWTAuthenticationClaimsSet();

		assertEquals(clientID.getValue(), assertion.getClientID().getValue());
		assertEquals(clientID.getValue(), assertion.getIssuer().getValue());
		assertEquals(clientID.getValue(), assertion.getSubject().getValue());
		assertEquals(audience.getValue(), assertion.getAudience().get(0).getValue());
		assertEquals(exp.getTime(), assertion.getExpirationTime().getTime());
		assertEquals(nbf.getTime(), assertion.getNotBeforeTime().getTime());
		assertEquals(iat.getTime(), assertion.getIssueTime().getTime());
		assertEquals(jti.getValue(), assertion.getJWTID().getValue());
	}


	public void testWithJWTHelper()
		throws Exception {

		ClientID clientID = new ClientID("123");
		URI tokenEndpoint = new URI("https://c2id.com/token");
		Secret secret = new Secret(256 / 8); // generate 256 bit secret

		ClientSecretJWT clientSecretJWT = new ClientSecretJWT(clientID, tokenEndpoint, JWSAlgorithm.HS256, secret);

		clientSecretJWT = ClientSecretJWT.parse(clientSecretJWT.toParameters());

		assertTrue(clientSecretJWT.getClientAssertion().verify(new MACVerifier(secret.getValueBytes())));

		assertEquals(clientID, clientSecretJWT.getJWTAuthenticationClaimsSet().getClientID());
		assertEquals(clientID.getValue(), clientSecretJWT.getJWTAuthenticationClaimsSet().getIssuer().getValue());
		assertEquals(clientID.getValue(), clientSecretJWT.getJWTAuthenticationClaimsSet().getSubject().getValue());
		assertEquals(tokenEndpoint.toString(), clientSecretJWT.getJWTAuthenticationClaimsSet().getAudience().get(0).getValue());

		// 4 min < exp < 6 min
		final long now = new Date().getTime();
		final Date fourMinutesFromNow = new Date(now + 4*60*1000l);
		final Date sixMinutesFromNow = new Date(now + 6*60*1000l);
		assertTrue(clientSecretJWT.getJWTAuthenticationClaimsSet().getExpirationTime().after(fourMinutesFromNow));
		assertTrue(clientSecretJWT.getJWTAuthenticationClaimsSet().getExpirationTime().before(sixMinutesFromNow));
		assertNotNull(clientSecretJWT.getJWTAuthenticationClaimsSet().getJWTID());
		assertNull(clientSecretJWT.getJWTAuthenticationClaimsSet().getIssueTime());
		assertNull(clientSecretJWT.getJWTAuthenticationClaimsSet().getNotBeforeTime());
	}
}

package com.nimbusds.oauth2.sdk.auth;


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

		Set<JWSAlgorithm> algs = ClientSecretJWT.getSupportedJWAs();

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

		JWTAuthenticationClaimsSet assertion = new JWTAuthenticationClaimsSet(clientID, audience, exp, nbf, iat, jti);

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
		assertEquals(audience.getValue(), assertion.getAudience().getValue());
		assertEquals(exp.getTime(), assertion.getExpirationTime().getTime());
		assertEquals(nbf.getTime(), assertion.getNotBeforeTime().getTime());
		assertEquals(iat.getTime(), assertion.getIssueTime().getTime());
		assertEquals(jti.getValue(), assertion.getJWTID().getValue());

		System.out.println("Client secret JWT expiration: " + assertion.getExpirationTime());
		System.out.println("Client secret JWT issue date: " + assertion.getIssueTime());
		System.out.println("Client secret JWT not before: " + assertion.getNotBeforeTime());
	}
}

package com.nimbusds.oauth2.sdk.jose.jwk;


import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

import com.nimbusds.jose.jwk.*;
import com.nimbusds.oauth2.sdk.id.ClientID;
import junit.framework.TestCase;


/**
 * Tests the immutable JWK set source.
 */
public class ImmutableJWKSetTest extends TestCase {
	

	public void testRun()
		throws Exception {

		KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
		pairGen.initialize(2048);
		KeyPair keyPair = pairGen.generateKeyPair();

		RSAKey rsaJWK = new RSAKey.Builder((RSAPublicKey)keyPair.getPublic())
			.privateKey((RSAPrivateKey)keyPair.getPrivate())
			.keyID("1")
			.build();

		JWKSet jwkSet = new JWKSet(rsaJWK);

		ImmutableJWKSet immutableJWKSet = new ImmutableJWKSet(new ClientID("123"), jwkSet);

		assertEquals(new ClientID("123"), immutableJWKSet.getOwner());
		assertEquals(jwkSet, immutableJWKSet.getJWKSet());

		List<JWK> matches = immutableJWKSet.get(new ClientID("123"), new JWKSelector(new JWKMatcher.Builder().keyID("1").build()));
		RSAKey m1 = (RSAKey)matches.get(0);
		assertEquals(rsaJWK.getModulus(), m1.getModulus());
		assertEquals(rsaJWK.getPublicExponent(), m1.getPublicExponent());
		assertEquals(rsaJWK.getPrivateExponent(), m1.getPrivateExponent());
		assertEquals(1, matches.size());
	}


	public void testOwnerMismatch()
		throws Exception {

		KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
		pairGen.initialize(2048);
		KeyPair keyPair = pairGen.generateKeyPair();

		RSAKey rsaJWK = new RSAKey.Builder((RSAPublicKey)keyPair.getPublic())
			.privateKey((RSAPrivateKey)keyPair.getPrivate())
			.keyID("1")
			.build();

		JWKSet jwkSet = new JWKSet(rsaJWK);

		ImmutableJWKSet immutableJWKSet = new ImmutableJWKSet(new ClientID("123"), jwkSet);

		assertEquals(new ClientID("123"), immutableJWKSet.getOwner());
		assertEquals(jwkSet, immutableJWKSet.getJWKSet());

		assertTrue(immutableJWKSet.get(new ClientID("xxx"), new JWKSelector(new JWKMatcher.Builder().keyID("1").build())).isEmpty());
	}
}

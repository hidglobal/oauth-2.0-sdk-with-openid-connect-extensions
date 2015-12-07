package com.nimbusds.oauth2.sdk.jose.jwk;


import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;

import static net.jadler.Jadler.*;

import com.nimbusds.jose.jwk.*;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.id.Issuer;
import junit.framework.TestCase;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;


/**
 * Remote JWK set source test.
 */
public class RemoteJWKSetTest extends TestCase {



	@Before
	public void setUp() {
		initJadler();
	}


	@After
	public void tearDown() {
		closeJadler();
	}


	@Test
	public void testSelectRSAByKeyID_defaultRetriever()
		throws Exception {

		KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
		pairGen.initialize(1024);
		KeyPair keyPair = pairGen.generateKeyPair();

		RSAKey rsaJWK1 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("1")
			.build();

		keyPair = pairGen.generateKeyPair();

		RSAKey rsaJWK2 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("2")
			.build();

		JWKSet jwkSet = new JWKSet(Arrays.asList((JWK)rsaJWK1, (JWK)rsaJWK2));

		Identifier id = new Issuer("https://c2id.com");
		URL jwkSetURL = new URL("http://localhost:" + port() + "/jwks.json");

		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/jwks.json")
			.respond()
			.withStatus(200)
			.withHeader("Content-Type", "application/json")
			.withBody(jwkSet.toJSONObject(true).toJSONString());

		RemoteJWKSet jwkSetSource = new RemoteJWKSet(id, jwkSetURL, null);

		assertEquals(id, jwkSetSource.getOwner());
		assertEquals(jwkSetURL, jwkSetSource.getJWKSetURL());
		assertNotNull(jwkSetSource.getResourceRetriever());

		JWKSet out = jwkSetSource.getJWKSet();
		assertTrue(out.getKeys().get(0) instanceof RSAKey);
		assertTrue(out.getKeys().get(1) instanceof RSAKey);
		assertEquals("1", out.getKeys().get(0).getKeyID());
		assertEquals("2", out.getKeys().get(1).getKeyID());
		assertEquals(2, out.getKeys().size());

		List<JWK> matches = jwkSetSource.get(id, new JWKSelector(new JWKMatcher.Builder().keyID("1").build()));

		RSAKey m1 = (RSAKey) matches.get(0);
		assertEquals(rsaJWK1.getPublicExponent(), m1.getPublicExponent());
		assertEquals(rsaJWK1.getModulus(), m1.getModulus());
		assertEquals("1", m1.getKeyID());

		assertEquals(1, matches.size());
	}


	@Test
	public void testInvalidJWKSetURL()
		throws Exception {

		KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
		pairGen.initialize(1024);
		KeyPair keyPair = pairGen.generateKeyPair();

		RSAKey rsaJWK1 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("1")
			.build();

		keyPair = pairGen.generateKeyPair();

		RSAKey rsaJWK2 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("2")
			.build();

		JWKSet jwkSet = new JWKSet(Arrays.asList((JWK)rsaJWK1, (JWK)rsaJWK2));

		Identifier id = new Issuer("https://c2id.com");
		URL jwkSetURL = new URL("http://localhost:" + port() + "/invalid-path");

		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/jwks.json")
			.respond()
			.withStatus(200)
			.withHeader("Content-Type", "application/json")
			.withBody(jwkSet.toJSONObject(true).toJSONString());

		RemoteJWKSet jwkSetSource = new RemoteJWKSet(id, jwkSetURL, null);

		assertEquals(id, jwkSetSource.getOwner());
		assertEquals(jwkSetURL, jwkSetSource.getJWKSetURL());

		assertNull(jwkSetSource.getJWKSet());

		List<JWK> matches = jwkSetSource.get(id, new JWKSelector(new JWKMatcher.Builder().keyID("1").build()));
		assertTrue(matches.isEmpty());
	}
}

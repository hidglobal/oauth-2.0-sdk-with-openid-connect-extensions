package com.nimbusds.openid.connect.sdk.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;

import org.junit.Test;

import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;

/**
 * Tests the {@link DefaultJWTDecoder} class.
 * 
 * @author <a href="mailto:mukherjisayan@gmail.com">Sayan Mukherji</a>
 */
public class DefaultJWTDecoderTest {

	/**
	 * Test method for {@link com.nimbusds.openid.connect.sdk.util.DefaultJWTDecoder#DefaultJWTDecoder()}.
	 */
	@Test
	public final void testDefaultJWTDecoderConstructor() {
		JWTDecoder jwtDecoder = new DefaultJWTDecoder();
		assertTrue(jwtDecoder instanceof DefaultJWTDecoder);
	}

	/**
	 * Test method for {@link com.nimbusds.openid.connect.sdk.util.DefaultJWTDecoder#getJWSVerifiers()}.
	 */
	@Test
	public final void testGetJWSVerifiersInitializeEmptyByDefault() {
		DefaultJWTDecoder jwtDecoder = new DefaultJWTDecoder();
		Collection<JWSVerifier> jwsVerifiers = jwtDecoder.getJWSVerifiers();
		assertNotNull(jwsVerifiers);
		assertEquals(0, jwsVerifiers.size());
	}

	/**
	 * Test method for {@link com.nimbusds.openid.connect.sdk.util.DefaultJWTDecoder#getJWEDecrypters()}.
	 */
	@Test
	public final void testGetJWEDecryptersInitializeEmptyByDefault() {
		DefaultJWTDecoder jwtDecoder = new DefaultJWTDecoder();
		Collection<JWEDecrypter> jweDecrypters = jwtDecoder.getJWEDecrypters();
		assertNotNull(jweDecrypters);
		assertEquals(0, jweDecrypters.size());
	}

	/**
	 * Test method for {@link com.nimbusds.openid.connect.sdk.util.DefaultJWTDecoder#addJWSVerifier(JWSVerifier)}
	 * using a {@link RSASSAVerifier} initializes a collection of verifiers with a size of all
	 * supported algorithms
	 */
	@Test
	public final void testAddJWSVerifierHappyPath() {
		try {
			final KeyPair keyPair = generateKeyPair("RSA", 1024);
			JWSVerifier verifier  = new RSASSAVerifier((RSAPublicKey) keyPair.getPublic());
			DefaultJWTDecoder jwtDecoder = new DefaultJWTDecoder();
			jwtDecoder.addJWSVerifier(verifier);
			Collection<JWSVerifier> verifiers = jwtDecoder.getJWSVerifiers();
			assertNotNull(verifiers);
			assertEquals(verifier.getAcceptedAlgorithms().size(), verifiers.size());
		} catch (NoSuchAlgorithmException e) {
			fail("Failed due to: " + e.getMessage());
		}
	}

	/**
	 * Test method for {@link com.nimbusds.openid.connect.sdk.util.DefaultJWTDecoder#addJWEDecrypter(JWEDecrypter)}
	 * using a {@link RSADecrypter} initializes a collection of decrypters with a size of all
	 * supported algorithms
	 */
	@Test
	public final void testAddJWEDecrypterHappyPath() {
		try {
			final KeyPair keyPair = generateKeyPair("RSA", 1024);
			final JWEDecrypter decrypter = new RSADecrypter((RSAPrivateKey)keyPair.getPrivate());
			DefaultJWTDecoder jwtDecoder = new DefaultJWTDecoder();
			jwtDecoder.addJWEDecrypter(decrypter);
			Collection<JWEDecrypter> decrypters = jwtDecoder.getJWEDecrypters();
			assertNotNull(decrypters);
			assertEquals(decrypter.getAcceptedAlgorithms().size(), decrypters.size());
		} catch (NoSuchAlgorithmException e) {
			fail("Failed due to: " + e.getMessage());
		}
	}

	protected KeyPair generateKeyPair(final String algorithm, final int size) throws NoSuchAlgorithmException {
		KeyPair keyPair;
		final KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
		generator.initialize(size, new SecureRandom());
		keyPair = generator.generateKeyPair();
		return keyPair;
	}
}

/**
 * 
 */
package com.nimbusds.openid.connect.sdk.util;

import static org.junit.Assert.*;

import java.util.Collection;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWSVerifier;

/**
 * Tests the {@link DefaultJWTDecoder} class.
 * 
 * @author <a href="mailto:mukherjisayan@gmail.com">Sayan Mukherji</a>
 */
public class DefaultJWTDecoderTest {

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
	}

	/**
	 * @throws java.lang.Exception
	 */
	@After
	public void tearDown() throws Exception {
	}

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

}

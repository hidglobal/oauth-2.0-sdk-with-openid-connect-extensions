package com.nimbusds.oauth2.sdk.auth;


import java.util.Date;

import com.nimbusds.jose.util.Base64;
import junit.framework.TestCase;


/**
 * Tests the secret / password class.
 */
public class SecretTest extends TestCase {


	public void testFullConstructor() {

		Date exp = new Date(new Date().getTime() + 3600*1000);
		Secret secret = new Secret("password", exp);
		assertEquals("password", secret.getValue());
		assertEquals(exp, secret.getExpirationDate());
		assertEquals(new Secret("password"), secret);
	}


	public void testEmptySecret() {

		Secret secret = new Secret("");
		assertEquals("", secret.getValue());
		assertEquals(0, secret.getValueBytes().length);
	}


	public void testErase() {

		Secret secret = new Secret("password");
		assertEquals("password".length(), secret.getValue().length());
		secret.erase();
		assertNull(secret.getValue());
	}


	public void testNotExpired() {

		Date future = new Date(new Date().getTime() + 3600*1000);
		Secret secret = new Secret("password", future);
		assertFalse(secret.expired());
	}


	public void testExpired() {

		Date past = new Date(new Date().getTime() - 3600*1000);
		Secret secret = new Secret("password", past);
		assertTrue(secret.expired());
	}


	public void testEquality() {

		assertTrue(new Secret("password").equals(new Secret("password")));
		assertTrue(new Secret("").equals(new Secret("")));

		// Compare erased secrets
		Secret s1 = new Secret("password");
		s1.erase();

		Secret s2 = new Secret("password");
		s2.erase();

		assertTrue(s1.equals(s2));

		// Ensure expiration date is ignored in comparison
		final Date now = new Date();
		final Date tomorrow = new Date(now.getTime() + 24*60*60*1000L);
		assertTrue(new Secret("password", tomorrow).equals(new Secret("password", new Date())));
	}


	public void testInequality() {

		assertFalse(new Secret("password").equals(new Secret("passw0rd")));
		assertFalse(new Secret("password").equals(new Secret("")));

		Secret erased = new Secret("password");
		erased.erase();

		assertFalse(erased.equals(new Secret("password")));
	}
	
	
	public void testGenerateDefault() {
		
		Secret secret = new Secret();
		
		// Base64 < encoded byte length
		assertEquals(Secret.DEFAULT_BYTE_LENGTH, new Base64(secret.getValue()).decode().length);
	}


	public void testGenerate() {

		Secret secret = new Secret(32);

		// Base64 < encoded byte length
		assertEquals(32, new Base64(secret.getValue()).decode().length);
	}
}

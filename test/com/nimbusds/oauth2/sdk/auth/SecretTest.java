package com.nimbusds.oauth2.sdk.auth;


import java.util.Date;

import junit.framework.TestCase;


/**
 * Tests the secret / password class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-02-25)
 */
public class SecretTest extends TestCase {


	public void testFullConstructor() {

		Date exp = new Date(new Date().getTime() + 3600*1000);
	
		Secret secret = new Secret("password", exp);

		assertEquals("password", secret.getValue());

		assertEquals(exp, secret.getExpirationDate());

		assertEquals(new Secret("password"), secret);
	}


	public void testErase() {

		Secret secret = new Secret();

		System.out.println("Secret: " + secret.getValue());

		assertEquals(32, secret.getValue().length());

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
}

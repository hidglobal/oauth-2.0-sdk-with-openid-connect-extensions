package com.nimbusds.openid.connect.sdk;


import junit.framework.TestCase;

import com.nimbusds.jose.util.Base64;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Tests the Nonce class.
 */
public class NonceTest extends TestCase {


	public void testDefaultConstructor() {

		Nonce nonce = new Nonce();

		System.out.println("Generated nonce: " + nonce);

		assertEquals(Identifier.DEFAULT_BYTE_LENGTH, new Base64(nonce.getValue()).decode().length);
	}


	public void testIntConstructor() {

		Nonce nonce =  new Nonce(1);

		System.out.println("Generated nonce: " + nonce);
		assertEquals(1, new Base64(nonce.getValue()).decode().length);

	}


	public void testIntConstructorZero() {

		try {
			new Nonce(0);

			fail();

		} catch (IllegalArgumentException e) {

			// ok
		}
	}


	public void testIntConstructorNegative() {

		try {
			new Nonce(-1);

			fail();

		} catch (IllegalArgumentException e) {

			// ok
		}
	}


	public void testEquality() {

		Nonce n1 = new Nonce("abc");
		Nonce n2 = new Nonce("abc");

		assertTrue(n1.equals(n2));
	}


	public void testInequality() {

		Nonce n1 = new Nonce("abc");
		Nonce n2 = new Nonce("xyz");

		assertFalse(n1.equals(n2));
	}
}
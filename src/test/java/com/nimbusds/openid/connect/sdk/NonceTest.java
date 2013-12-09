package com.nimbusds.openid.connect.sdk;


import junit.framework.TestCase;

import org.apache.commons.codec.binary.Base64;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Tests the Nonce class.
 */
public class NonceTest extends TestCase {


	public void testDefaultConstructor() {

		Nonce nonce = new Nonce();

		System.out.println("Generated nonce: " + nonce);

		assertEquals(Identifier.DEFAULT_BYTE_LENGTH, Base64.decodeBase64(nonce.getValue()).length);
	}


	public void testIntConstructor() {

		Nonce nonce =  new Nonce(1);

		System.out.println("Generated nonce: " + nonce);
		assertEquals(1, Base64.decodeBase64(nonce.getValue()).length);

	}


	public void testIntConstructorZero() {

		try {
			Nonce nonceZero = new Nonce(0);

			fail("Failed to raise exception");

		} catch (IllegalArgumentException e) {

			// ok
		}
	}


	public void testIntConstructorNegative() {

		try {
			Nonce nonceZero = new Nonce(-1);

			fail("Failed to raise exception");

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
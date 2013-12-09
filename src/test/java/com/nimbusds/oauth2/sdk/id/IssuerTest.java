package com.nimbusds.oauth2.sdk.id;


import java.net.MalformedURLException;
import java.net.URL;

import junit.framework.TestCase;


/**
 * Tests the issuer identifier class.
 */
public class IssuerTest extends TestCase {


	public void testConstructor() {

		Issuer iss = new Issuer("https://c2id.com");

		assertEquals("https://c2id.com", iss.getValue());
		assertEquals("https://c2id.com", iss.toString());
	}


	public void testStaticStringValidationMethods() {

		assertTrue(Issuer.isValid("https://c2id.com/"));
		assertTrue(Issuer.isValid("https://c2id.com/oidc/"));

		assertFalse(Issuer.isValid((String)null));
		assertFalse(Issuer.isValid("http://c2id.com"));
		assertFalse(Issuer.isValid("https://c2id.com?query=abc"));
		assertFalse(Issuer.isValid("https://c2id.com/oidc/#abc"));
		assertFalse(Issuer.isValid("https://c2id.com/oidc/?query=abc#abc"));
		assertFalse(Issuer.isValid("ftp://c2id.com/oidc/?query=abc#abc"));
	}


	public void testStaticIssuerValidationMethods() {

		assertTrue(Issuer.isValid(new Issuer("https://c2id.com/")));
		assertTrue(Issuer.isValid(new Issuer("https://c2id.com/oidc/")));

		assertFalse(Issuer.isValid((Issuer)null));
		assertFalse(Issuer.isValid(new Issuer("http://c2id.com")));
		assertFalse(Issuer.isValid(new Issuer("https://c2id.com?query=abc")));
		assertFalse(Issuer.isValid(new Issuer("https://c2id.com/oidc/#abc")));
		assertFalse(Issuer.isValid(new Issuer("https://c2id.com/oidc/?query=abc#abc")));
		assertFalse(Issuer.isValid(new Issuer("ftp://c2id.com/oidc/?query=abc#abc")));
	}


	public void testStaticURLValidationMethods()
		throws MalformedURLException {

		assertTrue(Issuer.isValid(new URL("https://c2id.com/")));
		assertTrue(Issuer.isValid(new URL("https://c2id.com/oidc/")));

		assertFalse(Issuer.isValid((URL)null));
		assertFalse(Issuer.isValid(new URL("http://c2id.com")));
		assertFalse(Issuer.isValid(new URL("https://c2id.com?query=abc")));
		assertFalse(Issuer.isValid(new URL("https://c2id.com/oidc/#abc")));
		assertFalse(Issuer.isValid(new URL("https://c2id.com/oidc/?query=abc#abc")));
		assertFalse(Issuer.isValid(new URL("ftp://c2id.com/oidc/?query=abc#abc")));
	}


	public void testInstanceValidation() {

		assertTrue(new Issuer("https://c2id.com/").isValid());
		assertTrue(new Issuer("https://c2id.com/oidc/").isValid());

		assertFalse(new Issuer("http://c2id.com").isValid());
		assertFalse(new Issuer("https://c2id.com?query=abc").isValid());
		assertFalse(new Issuer("https://c2id.com/oidc/#abc").isValid());
		assertFalse(new Issuer("https://c2id.com/oidc/?query=abc#abc").isValid());
		assertFalse(new Issuer("ftp://c2id.com/oidc/?query=abc#abc").isValid());
	}
}

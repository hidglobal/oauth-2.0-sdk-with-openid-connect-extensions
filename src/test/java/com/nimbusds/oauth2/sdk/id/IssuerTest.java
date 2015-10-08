package com.nimbusds.oauth2.sdk.id;


import java.net.URISyntaxException;
import java.net.URI;

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


	public void testStaticURIValidationMethods()
		throws URISyntaxException {

		assertTrue(Issuer.isValid(new URI("https://c2id.com/")));
		assertTrue(Issuer.isValid(new URI("https://c2id.com/oidc/")));

		assertFalse(Issuer.isValid((URI)null));
		assertFalse(Issuer.isValid(new URI("http://c2id.com")));
		assertFalse(Issuer.isValid(new URI("https://c2id.com?query=abc")));
		assertFalse(Issuer.isValid(new URI("https://c2id.com/oidc/#abc")));
		assertFalse(Issuer.isValid(new URI("https://c2id.com/oidc/?query=abc#abc")));
		assertFalse(Issuer.isValid(new URI("ftp://c2id.com/oidc/?query=abc#abc")));
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


	public void testURIConstructor() {

		assertEquals("https://c2id.com", new Issuer(URI.create("https://c2id.com")).getValue());
		assertTrue(new Issuer(URI.create("https://c2id.com")).equals(new Issuer("https://c2id.com")));
	}


	public void testClientIDConstructor() {

		assertEquals("123", new Issuer(new ClientID("123")).getValue());
		assertTrue(new Issuer("123").equals(new Issuer(new ClientID("123"))));
	}
}

package com.nimbusds.oauth2.sdk;


import java.net.URI;

import junit.framework.TestCase;


/**
 * Tests the error object class.
 */
public class ErrorObjectTest extends TestCase {


	public void testConstructor1()
		throws Exception {

		ErrorObject eo = new ErrorObject("access_denied");

		assertEquals("access_denied", eo.getCode());
		assertNull(eo.getDescription());
		assertNull(eo.getURI());
		assertEquals(0, eo.getHTTPStatusCode());
	}


	public void testConstructor2()
		throws Exception {

		ErrorObject eo = new ErrorObject("access_denied", "Access denied");

		assertEquals("access_denied", eo.getCode());
		assertEquals("Access denied", eo.getDescription());
		assertNull(eo.getURI());
		assertEquals(0, eo.getHTTPStatusCode());
	}


	public void testConstructor3()
		throws Exception {

		ErrorObject eo = new ErrorObject("access_denied", "Access denied", 403);

		assertEquals("access_denied", eo.getCode());
		assertEquals("Access denied", eo.getDescription());
		assertNull(eo.getURI());
		assertEquals(403, eo.getHTTPStatusCode());
	}


	public void testConstructor4()
		throws Exception {

		ErrorObject eo = new ErrorObject("access_denied", "Access denied", 403, new URI("https://c2id.com/errors/access_denied"));

		assertEquals("access_denied", eo.getCode());
		assertEquals("Access denied", eo.getDescription());
		assertEquals(new URI("https://c2id.com/errors/access_denied"), eo.getURI());
		assertEquals(403, eo.getHTTPStatusCode());
	}
}

package com.nimbusds.oauth2.sdk;


import junit.framework.TestCase;


/**
 * Tests the response mode class.
 */
public class ResponseModeTest extends TestCase {


	public void testConstants() {

		assertEquals("query", ResponseMode.QUERY.getValue());
		assertEquals("fragment", ResponseMode.FRAGMENT.getValue());
		assertEquals("form_post", ResponseMode.FORM_POST.getValue());
	}


	public void testConstructor() {

		ResponseMode mode = new ResponseMode("query");
		assertEquals("query", mode.getValue());
	}


	public void testEquality() {

		assertTrue(new ResponseMode("query").equals(new ResponseMode("query")));
	}


	public void testInequality() {

		assertFalse(new ResponseMode("fragment").equals(new ResponseMode("query")));
	}
}

package com.nimbusds.openid.connect.sdk;


import junit.framework.TestCase;


/**
 * Tests the response mode class.
 *
 * @author Vladimir Dzhuvinov
 */
public class ResponseModeTest extends TestCase {


	public void testConstants() {

		assertEquals("query", ResponseMode.QUERY.getValue());
		assertEquals("fragment", ResponseMode.FRAGMENT.getValue());
		assertEquals("form_post", ResponseMode.FORM_POST.getValue());
	}


	public void testParseConstants() {

		assertEquals(ResponseMode.QUERY, ResponseMode.parse("query"));
		assertEquals(ResponseMode.FRAGMENT, ResponseMode.parse("fragment"));
		assertEquals(ResponseMode.FORM_POST, ResponseMode.parse("form_post"));
	}


	public void testCustom() {

		ResponseMode rm = new ResponseMode("postMessage");

		assertEquals("postMessage", rm.getValue());

		assertEquals("postMessage", ResponseMode.parse("postMessage").getValue());
	}
}

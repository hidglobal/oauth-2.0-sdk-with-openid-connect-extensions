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
}

package com.nimbusds.oauth2.sdk;


import junit.framework.TestCase;


/**
 * Tests the response type class.
 *
 * @author Vladimir Dzhuvinov
 */
public class ResponseTypeTest extends TestCase {


	public void testConstants() {

		assertEquals("code", ResponseType.CODE.toString());

		assertEquals("token", ResponseType.TOKEN.toString());
	}
}

package com.nimbusds.oauth2.sdk;


import junit.framework.TestCase;


/**
 * Tests the response type class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-19)
 */
public class ResponseTypeTest extends TestCase {


	public void testConstants() {

		assertEquals("code", ResponseType.CODE.toString());

		assertEquals("token", ResponseType.TOKEN.toString());
	}
}

package com.nimbusds.openid.connect.sdk.rp;


import junit.framework.TestCase;


/**
 * Tests the application type enumeration.
 */
public class ApplicationTypeTest extends TestCase {


	public void testIdentifiers() {

		assertEquals("web", ApplicationType.WEB.toString());
		assertEquals("native", ApplicationType.NATIVE.toString());
	}


	public void testDefault() {

		assertEquals(ApplicationType.WEB, ApplicationType.getDefault());
	}
}

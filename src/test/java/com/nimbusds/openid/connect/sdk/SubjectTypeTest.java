package com.nimbusds.openid.connect.sdk;


import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;


/**
 * Tests the SubjectType class.
 *
 * @author Vladimir Dzhuvinov
 */
public class SubjectTypeTest extends TestCase {

	public void testToString() {

		assertEquals("pairwise", SubjectType.PAIRWISE.toString());
		assertEquals("public", SubjectType.PUBLIC.toString());
	}
	
	
	public void testParse()
		throws Exception {
		
		assertEquals(SubjectType.PAIRWISE, SubjectType.parse("pairwise"));
		assertEquals(SubjectType.PUBLIC, SubjectType.parse("public"));
	}
	
	
	public void testParseExceptionNull() {
		
		try {
			SubjectType.parse(null);
			
			fail("Failed to raise parse exception");
			
		} catch (ParseException e) {
			// ok
		}
	}
	
	
	public void testParseInvalidConstant() {
		
		try {
			SubjectType.parse("abc");
			
			fail("Failed to raise exception");
			
		} catch (ParseException e) {
			// ok
		}
	}
}
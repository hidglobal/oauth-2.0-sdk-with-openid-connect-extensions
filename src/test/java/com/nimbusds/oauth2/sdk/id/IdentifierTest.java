package com.nimbusds.oauth2.sdk.id;


import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Tests the base Identifier class.
 */
public class IdentifierTest {
	
	@Test
	public void testConstant() {
		
		assertEquals(32, Identifier.DEFAULT_BYTE_LENGTH);
	}
}
package com.nimbusds.oauth2.sdk.id;


import java.io.Serializable;

import junit.framework.TestCase;


/**
 * Tests the base Identifier class.
 */
public class IdentifierTest extends TestCase {


	public void testConstant() {
		
		assertEquals(32, Identifier.DEFAULT_BYTE_LENGTH);
	}


	public void testForSerializableInstance() {

		assertTrue((new Identifier() {

			public boolean equals(final Object object) {
				return true;
			}

		}) instanceof Serializable);
	}
}
package com.nimbusds.oauth2.sdk;


import junit.framework.TestCase;


/**
 * Tests the scope token class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-19)
 */
public class ScopeTokenTest extends TestCase {


	public void testMinimalConstructor() {

		ScopeToken t = new ScopeToken("read");

		assertEquals("read", t.getValue());

		assertNull(t.getRequirement());
	}


	public void testFullConstructor() {

		ScopeToken t = new ScopeToken("write", ScopeToken.Requirement.OPTIONAL);

		assertEquals("write", t.getValue());

		assertEquals(ScopeToken.Requirement.OPTIONAL, t.getRequirement());
	}


	public void testEquality() {

		ScopeToken t1 = new ScopeToken("read");
		ScopeToken t2 = new ScopeToken("read");

		assertTrue(t1.equals(t2));
	}
}

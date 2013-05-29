package com.nimbusds.oauth2.sdk;


import junit.framework.TestCase;


/**
 * Tests the scope token class.
 *
 * @author Vladimir Dzhuvinov
 */
public class ScopeValueTest extends TestCase {


	public void testMinimalConstructor() {

		ScopeValue t = new ScopeValue("read");

		assertEquals("read", t.getValue());

		assertNull(t.getRequirement());
	}


	public void testFullConstructor() {

		ScopeValue t = new ScopeValue("write", ScopeValue.Requirement.OPTIONAL);

		assertEquals("write", t.getValue());

		assertEquals(ScopeValue.Requirement.OPTIONAL, t.getRequirement());
	}


	public void testEquality() {

		ScopeValue t1 = new ScopeValue("read");
		ScopeValue t2 = new ScopeValue("read");

		assertTrue(t1.equals(t2));
	}
}

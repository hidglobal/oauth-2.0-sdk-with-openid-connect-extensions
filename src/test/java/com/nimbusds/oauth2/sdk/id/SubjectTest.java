package com.nimbusds.oauth2.sdk.id;


import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import junit.framework.TestCase;


/**
 * Tests the subject class.
 */
public class SubjectTest extends TestCase {


	public void testCompareTo() {

		List<Subject> list = Arrays.asList(new Subject("bob"), new Subject("claire"), new Subject("alice"));

		Collections.sort(list);

		assertEquals("alice", list.get(0).getValue());
		assertEquals("bob", list.get(1).getValue());
		assertEquals("claire", list.get(2).getValue());
	}


	public void testCastToComparable() {

		Subject subject = new Subject("alice");

		assertTrue(subject instanceof Comparable);
	}
}

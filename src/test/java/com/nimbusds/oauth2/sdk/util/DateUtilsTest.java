package com.nimbusds.oauth2.sdk.util;


import java.util.Date;

import junit.framework.TestCase;


/**
 * Tests the date utilities.
 */
public class DateUtilsTest extends TestCase {


	public void testToSeconds() {

		final Date date = new Date(2000l);

		assertEquals(2, DateUtils.toSecondsSinceEpoch(date));
	}


	public void testFromSeconds() {

		assertTrue(new Date(2000l).equals(DateUtils.fromSecondsSinceEpoch(2)));
	}


	public void testRoundTrip() {

		final Date date = new Date(100000);

		final long ts = DateUtils.toSecondsSinceEpoch(date);

		assertTrue(date.equals(DateUtils.fromSecondsSinceEpoch(ts)));
	}
}

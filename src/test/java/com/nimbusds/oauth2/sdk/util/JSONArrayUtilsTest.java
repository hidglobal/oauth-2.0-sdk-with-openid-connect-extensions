package com.nimbusds.oauth2.sdk.util;


import junit.framework.TestCase;

import net.minidev.json.JSONArray;


/**
 * Tests the JSON array utility methods.
 */
public class JSONArrayUtilsTest extends TestCase {


	public void testJSONArrayParse()
		throws Exception {

		String s = "[\"apples\", \"pears\"]";

		JSONArray a = JSONArrayUtils.parse(s);
		assertEquals("apples", a.get(0));
		assertEquals("pears", a.get(1));
		assertEquals(2, a.size());
	}


	public void testParseWithTrailingWhiteSpace()
		throws Exception {

		assertEquals(0, JSONArrayUtils.parse("[] ").size());
		assertEquals(0, JSONArrayUtils.parse("[]\n").size());
		assertEquals(0, JSONArrayUtils.parse("[]\r\n").size());
	}
}

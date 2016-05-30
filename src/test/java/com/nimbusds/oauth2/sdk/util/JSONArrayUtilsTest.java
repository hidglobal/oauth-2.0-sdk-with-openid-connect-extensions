package com.nimbusds.oauth2.sdk.util;


import java.net.URI;
import java.util.List;

import com.nimbusds.oauth2.sdk.ParseException;
import junit.framework.TestCase;
import net.minidev.json.JSONArray;


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


	public void testToStringList() {

		JSONArray jsonArray = new JSONArray();
		jsonArray.add("apple");
		jsonArray.add(1);
		jsonArray.add(true);

		List<String> stringList = JSONArrayUtils.toStringList(jsonArray);
		assertEquals("apple", stringList.get(0));
		assertEquals("1", stringList.get(1));
		assertEquals("true", stringList.get(2));
		assertEquals(3, stringList.size());
	}


	public void testToStringListNullInput() {

		assertTrue(JSONArrayUtils.toStringList(null).isEmpty());
	}


	public void testToStringListEmptyInput() {

		assertTrue(JSONArrayUtils.toStringList(new JSONArray()).isEmpty());
	}


	public void testToURIList()
		throws ParseException {

		JSONArray jsonArray = new JSONArray();
		jsonArray.add("https://example.com");
		jsonArray.add("ldap://localhost");

		List<URI> uriList = JSONArrayUtils.toURIList(jsonArray);
		assertEquals("https://example.com", uriList.get(0).toString());
		assertEquals("ldap://localhost", uriList.get(1).toString());
		assertEquals(2, uriList.size());
	}


	public void testToURIList_parseException()
		throws ParseException {

		JSONArray jsonArray = new JSONArray();
		jsonArray.add("https://example.com");
		jsonArray.add("a b c");

		try {
			System.out.println(JSONArrayUtils.toURIList(jsonArray));
			fail();
		} catch (ParseException e) {
			assertEquals("Illegal URI: Illegal character in path at index 1: a b c", e.getMessage());
		}
	}


	public void testToURIListNullInput()
		throws ParseException {

		assertTrue(JSONArrayUtils.toURIList(null).isEmpty());
	}


	public void testToURIListEmptyInput()
		throws ParseException {

		assertTrue(JSONArrayUtils.toURIList(new JSONArray()).isEmpty());
	}
}

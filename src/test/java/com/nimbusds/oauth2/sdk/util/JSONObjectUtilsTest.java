package com.nimbusds.oauth2.sdk.util;


import java.util.Arrays;

import junit.framework.TestCase;

import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;

import com.nimbusds.oauth2.sdk.ClientType;
import com.nimbusds.oauth2.sdk.ParseException;


/**
 * Tests the JSON object utility methods.
 */
public class JSONObjectUtilsTest extends TestCase {
	
	
	public static JSONObject getTestJSONObject() {
	
		JSONObject o = new JSONObject();
		
		o.put("bool", true);
		o.put("int", 100);
		o.put("long", 500l);
		o.put("float", 3.14f);
		o.put("double", 3.1415d);
		o.put("string", "Alice");
		o.put("url", "http://server.example.com/cb/");
		o.put("email", "alice@wonderland.net");
		o.put("client_type", "public");
		o.put("aud", Arrays.asList("client-1", "client-2"));
		
		JSONParser parser = new JSONParser(JSONParser.USE_HI_PRECISION_FLOAT);
		
		try {
			o = (JSONObject)parser.parse(o.toString());
			
		} catch (net.minidev.json.parser.ParseException e) {
		
			fail(e.getMessage());
		}
		
		return o;
	}
	
	
	public void testJSONObjectParse() {
	
		String s = "{\"apples\":3, \"pears\":\"none\"}";
		
		JSONObject o = null;
		
		try {
			o = JSONObjectUtils.parseJSONObject(s);
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertNotNull(o);
		
		assertEquals(new Long(3), (Long)o.get("apples"));
		assertEquals("none", (String)o.get("pears"));
	}
	
	
	public void testJSONObjectParseException() {
	
		String s = "{\"apples\":3, ";
		
		JSONObject o = null;
		
		try {
			o = JSONObjectUtils.parseJSONObject(s);
			
			fail("Failed to raise exception");
			
		} catch (ParseException e) {
		
			// ok
		}
	}
	
	
	public void testJSONObjectObjectParseExceptionNull() {
	
		try {
			JSONObjectUtils.parseJSONObject(null);
			
			fail("Failed to raise exception");
			
		} catch (ParseException e) {
		
			fail("Parse exception not expected here");
		
		} catch (NullPointerException e) {
		
			// ok
		}
	}
	
	
	public void testJSONObjectObjectParseExceptionNullEntity() {
	
		try {
			JSONObjectUtils.parseJSONObject("null");
			
			fail("Failed to raise exception");
		
		} catch (ParseException e) {
		
			// ok
		}
	}
	
	
	public void testJSONObjectObjectParseExceptionEmptyString() {
	
		try {
			JSONObjectUtils.parseJSONObject("");
			
			fail("Failed to raise exception");
		
		} catch (ParseException e) {
		
			// ok
		}
	}
	
	
	public void testJSONObjectObjectParseExceptionWhitespaceString() {
	
		try {
			JSONObjectUtils.parseJSONObject(" ");
			
			fail("Failed to raise exception");
		
		} catch (ParseException e) {
		
			// ok
		}
	}
	
	
	public void testGetters() {
	
		JSONObject o = getTestJSONObject();
		
		try {
			assertEquals(true, JSONObjectUtils.getBoolean(o, "bool"));
			assertEquals(100, JSONObjectUtils.getInt(o, "int"));
			assertEquals(500l, JSONObjectUtils.getLong(o, "long"));
			assertEquals(3.14f, JSONObjectUtils.getFloat(o, "float"));
			assertEquals(3.1415d, JSONObjectUtils.getDouble(o, "double"));
			assertEquals("Alice", JSONObjectUtils.getString(o, "string"));
			assertEquals("http://server.example.com/cb/", JSONObjectUtils.getURL(o, "url").toString());
			assertEquals("alice@wonderland.net", JSONObjectUtils.getEmail(o, "email").toString());
			assertEquals(ClientType.PUBLIC, JSONObjectUtils.getEnum(o, "client_type", ClientType.class));

			assertTrue(Arrays.asList("client-1", "client-2").containsAll(JSONObjectUtils.getList(o, "aud")));
			assertTrue(Arrays.asList("client-1", "client-2").containsAll(JSONObjectUtils.getJSONArray(o, "aud")));
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
	}
}

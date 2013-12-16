package com.nimbusds.oauth2.sdk;


import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;

import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;


/**
 * Tests the response type class.
 */
public class ResponseTypeTest extends TestCase {
	
	
	public void testConstants() {

		assertEquals("code", ResponseType.Value.CODE.toString());
		assertEquals("token", ResponseType.Value.TOKEN.toString());
	}


	public void testVarargConstructor() {

		ResponseType rt = new ResponseType(ResponseType.Value.CODE, OIDCResponseTypeValue.ID_TOKEN);

		assertTrue(rt.contains(ResponseType.Value.CODE));
		assertTrue(rt.contains("code"));
		assertTrue(rt.contains(OIDCResponseTypeValue.ID_TOKEN));
		assertTrue(rt.contains("id_token"));
		assertEquals(2, rt.size());

		assertFalse(rt.contains(ResponseType.Value.TOKEN));
		assertFalse(rt.contains("token"));
	}


	public void testStringVarargConstructor() {

		ResponseType rt = new ResponseType("code", "id_token");

		assertTrue(rt.contains(ResponseType.Value.CODE));
		assertTrue(rt.contains(OIDCResponseTypeValue.ID_TOKEN));
		assertEquals(2, rt.size());
	}


	public void testStringVarargConstructorNull() {

		try {
			new ResponseType((String)null);
			fail();
		} catch (IllegalArgumentException e) {
			// ok
		}
	}


	public void testCodeFlowDetection() {

		ResponseType rt = new ResponseType();
		rt.add(ResponseType.Value.CODE);
		assertTrue(rt.impliesCodeFlow());
		assertFalse(rt.impliesImplicitFlow());
	}


	public void testImplicitFlowDetection() {

		ResponseType rt = new ResponseType();
		rt.add(ResponseType.Value.TOKEN);
		assertTrue(rt.impliesImplicitFlow());
		assertFalse(rt.impliesCodeFlow());
	}


	public void testSerializeAndParse() {

		ResponseType rt = new ResponseType();
		rt.add(ResponseType.Value.CODE);
		rt.add(new ResponseType.Value("id_token"));

		try {
			rt = ResponseType.parse(rt.toString());

		} catch (ParseException e) {

			fail(e.getMessage());
		}

		assertTrue(rt.contains(ResponseType.Value.CODE));
		assertTrue(rt.contains(new ResponseType.Value("id_token")));
		assertEquals(2, rt.size());
	}


	public void testParseNull() {

		try {
			ResponseType.parse(null);

			fail("Failed to raise exception");
		
		} catch (ParseException e) {

			// ok
		}
	}


	public void testParseEmptyString() {

		try {
			ResponseType.parse(" ");

			fail("Failed to raise exception");
		
		} catch (ParseException e) {

			// ok
		}
	}


	public void testContains() {

		List<ResponseType> rtList = new ArrayList<ResponseType>();

		ResponseType rt1 = new ResponseType();
		rt1.add(ResponseType.Value.CODE);
		rtList.add(rt1);

		ResponseType rt2 = new ResponseType();
		rt2.add(ResponseType.Value.TOKEN);
		rt2.add(OIDCResponseTypeValue.ID_TOKEN);
		rtList.add(rt2);

		assertEquals(2, rtList.size());

		rt1 = new ResponseType();
		rt1.add(ResponseType.Value.CODE);
		rtList.add(rt1);
		assertTrue(rtList.contains(rt1));

		rt2 = new ResponseType();
		rt2.add(ResponseType.Value.TOKEN);
		rt2.add(OIDCResponseTypeValue.ID_TOKEN);
		rtList.add(rt2);
		assertTrue(rtList.contains(rt2));

		ResponseType rt3 = new ResponseType();
		rt3.add(OIDCResponseTypeValue.ID_TOKEN);

		assertFalse(rtList.contains(rt3));
	}


	public void testValueComparison() {

		assertEquals(ResponseType.Value.CODE, new ResponseType.Value("code"));
	}
}

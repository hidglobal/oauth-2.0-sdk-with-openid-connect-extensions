package com.nimbusds.openid.connect.sdk;


import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;


/**
 * Tests the Display class.
 */
public class DisplayTest extends TestCase {

	public void testToString() {

		assertEquals("page", Display.PAGE.toString());
		assertEquals("popup", Display.POPUP.toString());
		assertEquals("touch", Display.TOUCH.toString());
		assertEquals("wap", Display.WAP.toString());
	}


	public void testDefault() {

		assertEquals(Display.PAGE, Display.getDefault());
	}


	public void testParsePage()
		throws ParseException {

		assertEquals(Display.PAGE, Display.parse("page"));
	}


	public void testParsePopup()
		throws ParseException {

		assertEquals(Display.POPUP, Display.parse("popup"));
	}


	public void testParseTouch()
		throws ParseException {

		assertEquals(Display.TOUCH, Display.parse("touch"));
	}


	public void testParseWap()
		throws ParseException {

		assertEquals(Display.WAP, Display.parse("wap"));
	}


	public void testParseNull()
		throws ParseException {

		assertEquals(Display.PAGE, Display.parse(null));
	}


	public void testParseEmptyString()
		throws ParseException {

		assertEquals(Display.PAGE, Display.parse(""));
	}


	public void testParseException() {

		try {
			Display.parse("some-unsupported-display-type");

			fail("Failed to throw parse exception");

		} catch (ParseException e) {
			// ok
		}
	}
}
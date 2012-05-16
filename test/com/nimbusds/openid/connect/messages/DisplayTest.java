package com.nimbusds.openid.connect.messages;


import junit.framework.TestCase;

import com.nimbusds.openid.connect.ParseException;


/**
 * Tests display type parsing and default value.
 *
 * @author Vladimir Dzhuvinov
 * @version 0.2 (2012-03-23)
 */
public class DisplayTest extends TestCase {
	
	
	public void testDefault() {
	
		assertEquals(Display.PAGE, Display.getDefault());
	}
	
	
	public void testDefaultParseNull() {
	
		Display d = null;
	
		try {
			d = Display.parse(null);
		
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(Display.PAGE, d);
	}
	
	
	public void testDefaultParseEmptyString() {
	
		Display d = null;
	
		try {
			d = Display.parse("");
		
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(Display.PAGE, d);
	}
	
	
	public void testParsePage() {
	
		Display d = null;
	
		try {
			d = Display.parse("page");
		
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(Display.PAGE, d);
	}
	
	
	public void testParsePopup() {
	
		Display d = null;
	
		try {
			d = Display.parse("popup");
		
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(Display.POPUP, d);
	}
	
	
	public void testParseTouch() {
	
		Display d = null;
	
		try {
			d = Display.parse("touch");
		
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(Display.TOUCH, d);
	}
	
	
	public void testParseWap() {
	
		Display d = null;
	
		try {
			d = Display.parse("wap");
		
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(Display.WAP, d);
	}
}

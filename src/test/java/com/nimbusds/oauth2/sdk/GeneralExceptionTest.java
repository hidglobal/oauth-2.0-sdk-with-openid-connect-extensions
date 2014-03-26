package com.nimbusds.oauth2.sdk;


import java.net.URI;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;


/**
 * Tests the general exception class.
 */
public class GeneralExceptionTest extends TestCase {


	public void testConstructor1() {

		GeneralException e = new GeneralException("message");
		assertEquals("message", e.getMessage());

		assertNull(e.getErrorObject());
		assertNull(e.getClientID());
		assertNull(e.getRedirectionURI());
		assertNull(e.getState());
	}


	public void testConstructor2() {

		GeneralException e = new GeneralException("message", new IllegalArgumentException());
		assertEquals("message", e.getMessage());

		assertNull(e.getErrorObject());
		assertNull(e.getClientID());
		assertNull(e.getRedirectionURI());
		assertNull(e.getState());
	}


	public void testConstructor3() {

		GeneralException e = new GeneralException("message", OAuth2Error.INVALID_REQUEST, new IllegalArgumentException());
		assertEquals("message", e.getMessage());

		assertEquals(OAuth2Error.INVALID_REQUEST, e.getErrorObject());
		assertNull(e.getClientID());
		assertNull(e.getRedirectionURI());
		assertNull(e.getState());
	}


	public void testConstructor4()
		throws Exception {

		GeneralException e = new GeneralException(
			"message",
			OAuth2Error.INVALID_REQUEST,
			new ClientID("abc"),
			new URI("https://redirect.com"),
			new State("123"));

		assertEquals("message", e.getMessage());
		assertEquals(OAuth2Error.INVALID_REQUEST, e.getErrorObject());
		assertEquals("abc", e.getClientID().getValue());
		assertEquals("https://redirect.com", e.getRedirectionURI().toString());
		assertEquals("123", e.getState().getValue());
	}


	public void testConstructor5()
		throws Exception {

		GeneralException e = new GeneralException(
			"message",
			OAuth2Error.INVALID_REQUEST,
			new ClientID("abc"),
			new URI("https://redirect.com"),
			new State("123"),
			new IllegalArgumentException());

		assertEquals("message", e.getMessage());
		assertEquals(OAuth2Error.INVALID_REQUEST, e.getErrorObject());
		assertEquals("abc", e.getClientID().getValue());
		assertEquals("https://redirect.com", e.getRedirectionURI().toString());
		assertEquals("123", e.getState().getValue());
	}
}

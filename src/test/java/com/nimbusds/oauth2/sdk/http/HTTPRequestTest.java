package com.nimbusds.oauth2.sdk.http;


import java.net.URL;
import java.util.Map;

import junit.framework.TestCase;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;


/**
 * Tests the HTTP request class.
 */
public class HTTPRequestTest extends TestCase {


	public void testConstructorAndAccessors()
		throws Exception {

		URL url = new URL("https://c2id.com/login");

		HTTPRequest request = new HTTPRequest(HTTPRequest.Method.POST, url);

		assertEquals(HTTPRequest.Method.POST, request.getMethod());
		assertEquals(url, request.getURL());

		request.ensureMethod(HTTPRequest.Method.POST);

		try {
			request.ensureMethod(HTTPRequest.Method.GET);
			fail();
		} catch (ParseException e) {
			// ok
		}

		assertNull(request.getContentType());
		request.setContentType(CommonContentTypes.APPLICATION_JSON);
		assertEquals(CommonContentTypes.APPLICATION_JSON, request.getContentType());

		assertNull(request.getAuthorization());
		request.setAuthorization("Bearer 123");
		assertEquals("Bearer 123", request.getAuthorization());

		assertNull(request.getQuery());
		request.setQuery("x=123&y=456");
		assertEquals("x=123&y=456", request.getQuery());

		Map<String,String> params = request.getQueryParameters();
		assertEquals("123", params.get("x"));
		assertEquals("456", params.get("y"));

		request.setQuery("{\"apples\":\"123\"}");
		JSONObject jsonObject = request.getQueryAsJSONObject();
		assertEquals("123", (String)jsonObject.get("apples"));
	}
}

package com.nimbusds.oauth2.sdk.http;


import java.net.URL;
import java.util.Map;

import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
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


	public void testParseJSONObject()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("http://localhost"));

		httpRequest.setContentType(CommonContentTypes.APPLICATION_JSON);

		httpRequest.setQuery("{\"apples\":30, \"pears\":\"green\"}");

		JSONObject jsonObject = httpRequest.getQueryAsJSONObject();

		assertEquals(30, JSONObjectUtils.getInt(jsonObject, "apples"));
		assertEquals("green", JSONObjectUtils.getString(jsonObject, "pears"));
		assertEquals(2, jsonObject.size());
	}


	public void testParseJSONObjectException()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("http://localhost"));

		httpRequest.setContentType(CommonContentTypes.APPLICATION_JSON);

		httpRequest.setQuery(" ");

		try {
			httpRequest.getQueryAsJSONObject();
			fail();
		} catch (ParseException e) {
			// ok
			assertEquals("Missing or empty HTTP query string / entity body", e.getMessage());
		}
	}


	// TODO Enable when connect2is server is available
	public void _test401Response()
		throws Exception {

		// Simulate token request with invalid token
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("http://localhost:8080/c2id/token"));
		httpRequest.setAuthorization("Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW");
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		httpRequest.setQuery("grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA" +
			"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb");

		HTTPResponse httpResponse = httpRequest.send();

		assertEquals(401, httpResponse.getStatusCode());
		assertEquals("Bearer", httpResponse.getWWWAuthenticate());

		System.out.println("Token error: " + httpResponse.getContent());
	}
}

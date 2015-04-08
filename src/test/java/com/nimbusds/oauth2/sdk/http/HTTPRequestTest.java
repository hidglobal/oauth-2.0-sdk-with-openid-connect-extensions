package com.nimbusds.oauth2.sdk.http;


import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Map;

import junit.framework.TestCase;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


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
		assertEquals(CommonContentTypes.APPLICATION_JSON.toString(), request.getContentType().toString());

		assertNull(request.getAuthorization());
		request.setAuthorization("Bearer 123");
		assertEquals("Bearer 123", request.getAuthorization());

		assertNull(request.getAccept());
		request.setAccept("text/plain");
		assertEquals("text/plain", request.getAccept());

		assertNull(request.getQuery());
		request.setQuery("x=123&y=456");
		assertEquals("x=123&y=456", request.getQuery());

		Map<String,String> params = request.getQueryParameters();
		assertEquals("123", params.get("x"));
		assertEquals("456", params.get("y"));

		request.setQuery("{\"apples\":\"123\"}");
		JSONObject jsonObject = request.getQueryAsJSONObject();
		assertEquals("123", (String)jsonObject.get("apples"));

		request.setFragment("fragment");
		assertEquals("fragment", request.getFragment());

		assertEquals(0, request.getConnectTimeout());
		request.setConnectTimeout(250);
		assertEquals(250, request.getConnectTimeout());

		assertEquals(0, request.getReadTimeout());
		request.setReadTimeout(750);
		assertEquals(750, request.getReadTimeout());
	}
	
	
	public void testConstructFromServletRequestWithEntityBody()
		throws Exception {

		MockServletRequest servletRequest = new MockServletRequest();
		servletRequest.setMethod("POST");
		servletRequest.setHeader("Content-Type", CommonContentTypes.APPLICATION_URLENCODED.toString());
		servletRequest.setLocalAddr("c2id.com");
		servletRequest.setLocalPort(8080);
		servletRequest.setRequestURI("/token");
		servletRequest.setQueryString(null);
		servletRequest.setEntityBody("token=abc&type=bearer");

		HTTPRequest httpRequest = new HTTPRequest(servletRequest);
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED.toString(), httpRequest.getContentType().toString());
		assertNull(httpRequest.getAccept());
		assertNull(httpRequest.getAuthorization());
		Map<String,String> queryParams = httpRequest.getQueryParameters();
		assertEquals("abc", queryParams.get("token"));
		assertEquals("bearer", queryParams.get("type"));
		assertEquals(2, queryParams.size());
	}


	public void testConstructFromServletRequestWithQueryString()
		throws Exception {

		MockServletRequest servletRequest = new MockServletRequest();
		servletRequest.setMethod("GET");
		servletRequest.setLocalAddr("c2id.com");
		servletRequest.setLocalPort(8080);
		servletRequest.setRequestURI("/token");
		servletRequest.setQueryString("token=abc&type=bearer");

		HTTPRequest httpRequest = new HTTPRequest(servletRequest);
		assertEquals(HTTPRequest.Method.GET, httpRequest.getMethod());
		assertNull(httpRequest.getContentType());
		assertNull(httpRequest.getAccept());
		assertNull(httpRequest.getAuthorization());
		Map<String,String> queryParams = httpRequest.getQueryParameters();
		assertEquals("abc", queryParams.get("token"));
		assertEquals("bearer", queryParams.get("type"));
		assertEquals(2, queryParams.size());
	}


	public void testServletRequestWithExceededEntityLengthLimit()
		throws Exception {

		MockServletRequest servletRequest = new MockServletRequest();
		servletRequest.setMethod("POST");
		servletRequest.setHeader("Content-Type", CommonContentTypes.APPLICATION_URLENCODED.toString());
		servletRequest.setLocalAddr("c2id.com");
		servletRequest.setLocalPort(8080);
		servletRequest.setRequestURI("/token");
		servletRequest.setQueryString(null);

		StringBuilder sb = new StringBuilder();
		for (int i=0; i < 1001; i++) {
			sb.append("a");
		}

		servletRequest.setEntityBody(sb.toString());

		try {
			new HTTPRequest(servletRequest, 1000);
			fail();
		} catch (IOException e) {
			assertEquals("Request entity body is too large, limit is 1000 chars", e.getMessage());
		}
	}


	public void testServletRequestWithinEntityLengthLimit()
		throws Exception {

		MockServletRequest servletRequest = new MockServletRequest();
		servletRequest.setMethod("POST");
		servletRequest.setHeader("Content-Type", CommonContentTypes.APPLICATION_URLENCODED.toString());
		servletRequest.setLocalAddr("c2id.com");
		servletRequest.setLocalPort(8080);
		servletRequest.setRequestURI("/token");
		servletRequest.setQueryString(null);

		StringBuilder sb = new StringBuilder();
		for (int i=0; i < 1000; i++) {
			sb.append("a");
		}

		servletRequest.setEntityBody(sb.toString());

		new HTTPRequest(servletRequest, 1000);
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


	// TODO Enable when connect2is server is available, passes 2014-08-05
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


	// TODO Enable when connect2is server is available, passes 2014-08-05
	public void _testToHttpURLConnection()
		throws Exception {

		// Simulate token request with invalid token
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("http://localhost:8080/c2id/token"));
		httpRequest.setAuthorization("Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW");
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		httpRequest.setConnectTimeout(250);
		httpRequest.setReadTimeout(750);
		httpRequest.setQuery("grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA" +
			"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb");

		HttpURLConnection con = httpRequest.toHttpURLConnection();
		assertEquals("POST", con.getRequestMethod());
		assertEquals(250, con.getConnectTimeout());
		assertEquals(750, con.getReadTimeout());
	}


	public void testSend()
		throws Exception {

		// TODO
	}
}

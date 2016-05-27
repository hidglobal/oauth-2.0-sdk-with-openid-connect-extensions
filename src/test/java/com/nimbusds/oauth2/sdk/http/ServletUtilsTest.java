package com.nimbusds.oauth2.sdk.http;


import java.io.IOException;
import java.net.URI;
import java.util.Map;

import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import junit.framework.TestCase;
import net.minidev.json.JSONObject;


/**
 * Tests the HTTP to / from servet request / response.
 */
public class ServletUtilsTest extends TestCase {


	public void testConstructFromServletRequestWithJSONEntityBody()
		throws Exception {

		MockServletRequest servletRequest = new MockServletRequest();
		servletRequest.setMethod("POST");
		servletRequest.setHeader("Content-Type", CommonContentTypes.APPLICATION_JSON.toString());
		servletRequest.setLocalAddr("c2id.com");
		servletRequest.setLocalPort(8080);
		servletRequest.setRequestURI("/clients");
		servletRequest.setQueryString(null);
		String entityBody = "{\"grant_types\":[\"code\"]}";
		servletRequest.setEntityBody(entityBody);

		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(servletRequest);
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(CommonContentTypes.APPLICATION_JSON.toString(), httpRequest.getContentType().toString());
		assertNull(httpRequest.getAccept());
		assertNull(httpRequest.getAuthorization());
		assertEquals(entityBody, httpRequest.getQuery());
		JSONObject jsonObject = httpRequest.getQueryAsJSONObject();
		assertEquals("code", JSONObjectUtils.getStringArray(jsonObject, "grant_types")[0]);
		assertEquals(1, jsonObject.size());
	}



	public void testConstructFromServletRequestURLEncoded()
		throws Exception {

		MockServletRequest servletRequest = new MockServletRequest();
		servletRequest.setMethod("POST");
		servletRequest.setHeader("Content-Type", CommonContentTypes.APPLICATION_URLENCODED.toString());
		servletRequest.setLocalAddr("c2id.com");
		servletRequest.setLocalPort(8080);
		servletRequest.setRequestURI("/token");
		servletRequest.setQueryString(null);
		servletRequest.setEntityBody("");
		servletRequest.setParameter("token", "abc");
		servletRequest.setParameter("type", "bearer");

		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(servletRequest);
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED.toString(), httpRequest.getContentType().toString());
		assertNull(httpRequest.getAccept());
		assertNull(httpRequest.getAuthorization());
		Map<String, String> queryParams = httpRequest.getQueryParameters();
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

		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(servletRequest);
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
			ServletUtils.createHTTPRequest(servletRequest, 1000);
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

		ServletUtils.createHTTPRequest(servletRequest, 1000);
	}


	public void testRedirectApplyToServletResponse()
		throws Exception {

		HTTPResponse response = new HTTPResponse(302);
		response.setLocation(new URI("https://client.com/cb"));

		MockServletResponse servletResponse = new MockServletResponse();

		ServletUtils.applyHTTPResponse(response, servletResponse);

		assertFalse(response.indicatesSuccess());
		assertEquals(302, servletResponse.getStatus());
		assertEquals("https://client.com/cb", servletResponse.getHeader("Location"));
	}


	public void testJSONContentApplyToServletResponse()
		throws Exception {

		HTTPResponse response = new HTTPResponse(200);
		response.setContentType(CommonContentTypes.APPLICATION_JSON);
		response.setCacheControl("no-cache");
		response.setPragma("no-cache");
		response.setContent("{\"apples\":\"123\"}");

		MockServletResponse servletResponse = new MockServletResponse();

		ServletUtils.applyHTTPResponse(response, servletResponse);

		assertTrue(response.indicatesSuccess());
		assertEquals(200, servletResponse.getStatus());
		assertEquals("application/json; charset=UTF-8", servletResponse.getContentType());
		assertEquals("no-cache", servletResponse.getHeader("Cache-Control"));
		assertEquals("no-cache", servletResponse.getHeader("Pragma"));
		assertEquals("{\"apples\":\"123\"}", servletResponse.getContent());
	}
}

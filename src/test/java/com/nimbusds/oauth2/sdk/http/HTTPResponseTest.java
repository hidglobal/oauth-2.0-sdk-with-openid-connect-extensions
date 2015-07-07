package com.nimbusds.oauth2.sdk.http;


import java.net.URI;
import java.net.URISyntaxException;

import junit.framework.TestCase;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWT;

import com.nimbusds.oauth2.sdk.ParseException;


/**
 * Tests the HTTP response class.
 */
public class HTTPResponseTest extends TestCase {


	public void testConstructorAndAccessors()
		throws Exception {

		HTTPResponse response = new HTTPResponse(200);

		assertTrue(response.indicatesSuccess());
		assertEquals(200, response.getStatusCode());

		response.ensureStatusCode(200);
		response.ensureStatusCode(200, 201);

		try {
			response.ensureStatusCode(302);
			fail();
		} catch (ParseException e) {
			// ok
			assertEquals("Unexpected HTTP status code 200, must be [302]", e.getMessage());
		}

		assertNull(response.getContentType());
		response.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED.toString(), response.getContentType().toString());

		assertNull(response.getLocation());
		URI location = new URI("https://client.com/cb");
		response.setLocation(location);
		assertEquals(location, response.getLocation());

		assertNull(response.getCacheControl());
		response.setCacheControl("no-cache");
		assertEquals("no-cache", response.getCacheControl());

		assertNull(response.getPragma());
		response.setPragma("no-cache");
		assertEquals("no-cache", response.getPragma());

		assertNull(response.getWWWAuthenticate());
		response.setWWWAuthenticate("Basic");
		assertEquals("Basic", response.getWWWAuthenticate());

		assertNull(response.getContent());

		try {
			response.getContentAsJSONObject();
			fail();
		} catch (ParseException e) {
			// ok
		}

		try {
			response.getContentAsJWT();
			fail();
		} catch (ParseException e) {
			// ok
		}

		response.setContentType(CommonContentTypes.APPLICATION_JSON);
		response.setContent("{\"apples\":\"123\"}");
		assertEquals("{\"apples\":\"123\"}", response.getContent());

		JSONObject jsonObject = response.getContentAsJSONObject();
		assertEquals("123", (String)jsonObject.get("apples"));

		// From http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-13#section-3.1
		String exampleJWTString = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
			"." +
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
			"." +
			"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

		response.setContentType(CommonContentTypes.APPLICATION_JWT);
		response.setContent(exampleJWTString);

		JWT jwt = response.getContentAsJWT();
		assertEquals(JWSAlgorithm.HS256, jwt.getHeader().getAlgorithm());
	}


	public void testGetContentAsJSONArray()
		throws Exception {

		HTTPResponse response = new HTTPResponse(200);
		response.setContentType(CommonContentTypes.APPLICATION_JSON);
		response.setContent("[\"apples\",\"pears\"]");

		JSONArray array = response.getContentAsJSONArray();
		assertEquals("apples", array.get(0));
		assertEquals("pears", array.get(1));
		assertEquals(2, array.size());
	}


	public void testPreserveHeaderCase() {
		HTTPResponse response = new HTTPResponse(302);
		response.setHeader("Location", "http://example.org");

		assertEquals("Location", response.getHeaders().keySet().iterator().next());
	}


	public void testGetHeaderWithCaseMismatch()
		throws URISyntaxException{

		HTTPResponse response = new HTTPResponse(302);
		response.setHeader("location", "http://example.org");

		assertEquals(new URI("http://example.org"), response.getLocation());
	}


	public void testRemoveHeaderWithCaseMismatch()
		throws URISyntaxException{

		HTTPResponse response = new HTTPResponse(302);
		response.setHeader("location", "http://example.org");

		assertEquals(new URI("http://example.org"), response.getLocation());

		response.setHeader("LOCATION", null);

		assertNull(response.getLocation());
	}
}

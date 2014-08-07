package com.nimbusds.oauth2.sdk;


import java.net.URI;

import junit.framework.TestCase;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * Tests the error object class.
 */
public class ErrorObjectTest extends TestCase {


	public void testConstructor1()
		throws Exception {

		ErrorObject eo = new ErrorObject("access_denied");

		assertEquals("access_denied", eo.getCode());
		assertNull(eo.getDescription());
		assertNull(eo.getURI());
		assertEquals(0, eo.getHTTPStatusCode());

		assertEquals("access_denied", (String)eo.toJSONObject().get("error"));
		assertEquals(1, eo.toJSONObject().size());
	}


	public void testConstructor2()
		throws Exception {

		ErrorObject eo = new ErrorObject("access_denied", "Access denied");

		assertEquals("access_denied", eo.getCode());
		assertEquals("Access denied", eo.getDescription());
		assertNull(eo.getURI());
		assertEquals(0, eo.getHTTPStatusCode());

		assertEquals("access_denied", (String)eo.toJSONObject().get("error"));
		assertEquals("Access denied", (String)eo.toJSONObject().get("error_description"));
		assertEquals(2, eo.toJSONObject().size());
	}


	public void testConstructor3()
		throws Exception {

		ErrorObject eo = new ErrorObject("access_denied", "Access denied", 403);

		assertEquals("access_denied", eo.getCode());
		assertEquals("Access denied", eo.getDescription());
		assertNull(eo.getURI());
		assertEquals(403, eo.getHTTPStatusCode());

		assertEquals("access_denied", (String)eo.toJSONObject().get("error"));
		assertEquals("Access denied", (String)eo.toJSONObject().get("error_description"));
		assertEquals(2, eo.toJSONObject().size());
	}


	public void testConstructor4()
		throws Exception {

		ErrorObject eo = new ErrorObject("access_denied", "Access denied", 403, new URI("https://c2id.com/errors/access_denied"));

		assertEquals("access_denied", eo.getCode());
		assertEquals("Access denied", eo.getDescription());
		assertEquals(new URI("https://c2id.com/errors/access_denied"), eo.getURI());
		assertEquals(403, eo.getHTTPStatusCode());

		assertEquals("access_denied", (String)eo.toJSONObject().get("error"));
		assertEquals("Access denied", (String)eo.toJSONObject().get("error_description"));
		assertEquals("https://c2id.com/errors/access_denied", (String)eo.toJSONObject().get("error_uri"));
		assertEquals(3, eo.toJSONObject().size());
	}


	public void testParseFull()
		throws Exception {

		HTTPResponse httpResponse = new HTTPResponse(403);
		httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("error", "access_denied");
		jsonObject.put("error_description", "Access denied");
		jsonObject.put("error_uri", "https://c2id.com/errors/access_denied");

		httpResponse.setContent(jsonObject.toJSONString());

		ErrorObject errorObject = ErrorObject.parse(httpResponse);

		assertEquals(403, errorObject.getHTTPStatusCode());
		assertEquals("access_denied", errorObject.getCode());
		assertEquals("Access denied", errorObject.getDescription());
		assertEquals("https://c2id.com/errors/access_denied", errorObject.getURI().toString());
	}


	public void testParseWithOmittedURI()
		throws Exception {

		HTTPResponse httpResponse = new HTTPResponse(403);
		httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("error", "access_denied");
		jsonObject.put("error_description", "Access denied");

		httpResponse.setContent(jsonObject.toJSONString());

		ErrorObject errorObject = ErrorObject.parse(httpResponse);

		assertEquals(403, errorObject.getHTTPStatusCode());
		assertEquals("access_denied", errorObject.getCode());
		assertEquals("Access denied", errorObject.getDescription());
		assertNull(errorObject.getURI());
	}


	public void testParseWithCodeOnly()
		throws Exception {

		HTTPResponse httpResponse = new HTTPResponse(403);
		httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("error", "access_denied");

		httpResponse.setContent(jsonObject.toJSONString());

		ErrorObject errorObject = ErrorObject.parse(httpResponse);

		assertEquals(403, errorObject.getHTTPStatusCode());
		assertEquals("access_denied", errorObject.getCode());
		assertNull(errorObject.getDescription());
		assertNull(errorObject.getURI());
	}


	public void testParseNone()
		throws Exception {

		HTTPResponse httpResponse = new HTTPResponse(403);

		ErrorObject errorObject = ErrorObject.parse(httpResponse);

		assertEquals(403, errorObject.getHTTPStatusCode());
		assertNull(errorObject.getCode());
		assertNull(errorObject.getDescription());
		assertNull(errorObject.getURI());
	}
}

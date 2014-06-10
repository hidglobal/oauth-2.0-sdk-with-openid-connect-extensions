package com.nimbusds.oauth2.sdk.util;


import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.util.LinkedHashMap;
import java.util.Map;

import junit.framework.TestCase;



/**
 * Tests the URL utility methods.
 */
public class URLUtilsTest extends TestCase {
	
	
	public void testGetBaseURLSame()
		throws MalformedURLException {
	
		URL url = new URL("http://client.example.com:8080/endpoints/openid/connect/cb");
		
		URL baseURL = URLUtils.getBaseURL(url);
		
		assertEquals("http://client.example.com:8080/endpoints/openid/connect/cb", baseURL.toString());
	}
	
	
	public void testGetBaseURLTrim()
		throws MalformedURLException {
	
		URL url = new URL("http://client.example.com:8080/endpoints/openid/connect/cb?param1=one&param2=two");
		
		URL baseURL = URLUtils.getBaseURL(url);
		
		assertEquals("http://client.example.com:8080/endpoints/openid/connect/cb", baseURL.toString());
	}
	
	
	public void testJavaURLDecoder()
		throws Exception {
	
		final String decodedPlus = URLDecoder.decode("abc+def", "utf-8");
		final String decodedPerCent20 = URLDecoder.decode("abc%20def", "utf-8");
		
		assertEquals("abc def", decodedPlus);
		assertEquals("abc def", decodedPerCent20);
	}
	
	
	public void testSerializeParameters() {
	
		Map<String,String> params = new LinkedHashMap<>();
		
		params.put("response_type", "code id_token");
		params.put("client_id", "s6BhdRkqt3");
		params.put("redirect_uri", "https://client.example.com/cb");
		params.put("scope", "openid");
		params.put("nonce", "n-0S6_WzA2Mj");
		params.put("state", "af0ifjsldkj");
		
		String query = URLUtils.serializeParameters(params);
		
		assertNotNull(query);
		assertEquals("response_type=code+id_token" + 
		             "&client_id=s6BhdRkqt3" +
			     "&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb" +
			     "&scope=openid" +
			     "&nonce=n-0S6_WzA2Mj" +
			     "&state=af0ifjsldkj", query);
	}
	
	
	public void testSerializeParametersNull() {
	
		String query = URLUtils.serializeParameters(null);
		
		assertNotNull(query);
		assertTrue(query.isEmpty());
	}
	
	
	public void testParseParameters() {
	
		String query = "response_type=code%20id_token" +
				"&client_id=s6BhdRkqt3" +
				"&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb" +
				"&scope=openid" +
				"&nonce=n-0S6_WzA2Mj" +
				"&state=af0ifjsldkj";
	
		Map<String,String> params = URLUtils.parseParameters(query);
		
		String value;
		
		value = params.get("response_type");
		assertNotNull(value);
		assertEquals("code id_token", value);
		
		value = params.get("client_id");
		assertNotNull(value);
		assertEquals("s6BhdRkqt3", value);
		
		value = params.get("redirect_uri");
		assertNotNull(value);
		assertEquals("https://client.example.com/cb", value);
		
		value = params.get("scope");
		assertNotNull(value);
		assertEquals("openid", value);
		
		value = params.get("nonce");
		assertNotNull(value);
		assertEquals("n-0S6_WzA2Mj", value);
		
		value = params.get("state");
		assertNotNull(value);
		assertEquals("af0ifjsldkj", value);
	}


	public void testParseParametersNull() {
	
		String query = null;
		
		Map<String,String> params = URLUtils.parseParameters(query);
		
		assertNotNull(params);
		assertTrue(params.isEmpty());
	}


	public void testParseParametersEmpty() {

		String query = " ";

		assertTrue(URLUtils.parseParameters(query).isEmpty());
	}


	public void testParseParametersEnsureTrim() {

		String query = "\np1=abc&p2=def  \n";

		Map<String,String> params = URLUtils.parseParameters(query);

		assertEquals("abc", params.get("p1"));
		assertEquals("def", params.get("p2"));
		assertEquals(2, params.size());
	}
}

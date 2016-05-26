package com.nimbusds.oauth2.sdk.util;


import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.util.LinkedHashMap;
import java.util.Map;

import junit.framework.TestCase;



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
		
		assertEquals("response_type=code+id_token" +
		             "&client_id=s6BhdRkqt3" +
			     "&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb" +
			     "&scope=openid" +
			     "&nonce=n-0S6_WzA2Mj" +
			     "&state=af0ifjsldkj", query);
	}


	public void testSerializeParameters_nullValue() {

		Map<String,String> params = new LinkedHashMap<>();

		params.put("response_type", "code");
		params.put("display", null);

		String query = URLUtils.serializeParameters(params);

		assertEquals("response_type=code&display=", query);
	}
	
	
	public void testSerializeParametersNull() {
	
		String query = URLUtils.serializeParameters(null);
		
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

		assertEquals("code id_token", params.get("response_type"));
		assertEquals("s6BhdRkqt3", params.get("client_id"));
		assertEquals("https://client.example.com/cb", params.get("redirect_uri"));
		assertEquals("openid", params.get("scope"));
		assertEquals("n-0S6_WzA2Mj", params.get("nonce"));
		assertEquals("af0ifjsldkj", params.get("state"));
	}


	public void testParseParametersNull() {
	
		assertTrue(URLUtils.parseParameters(null).isEmpty());
	}


	public void testParseParametersEmpty() {

		assertTrue(URLUtils.parseParameters(" ").isEmpty());
	}


	public void testParseParametersEnsureTrim() {

		String query = "\np1=abc&p2=def  \n";

		Map<String,String> params = URLUtils.parseParameters(query);

		assertEquals("abc", params.get("p1"));
		assertEquals("def", params.get("p2"));
		assertEquals(2, params.size());
	}


	// See https://bitbucket.org/connect2id/openid-connect-dev-client/issues/5/stripping-equal-sign-from-access_code-in
	public void testDecodeQueryStringWithEscapedChars() {

		String fragment = "scope=openid+email+profile" +
			"&state=cVIe4g4D1J3tYtZgnTL-Po9QpozQJdikDCBp7KJorIQ" +
			"&code=1nf1ljB0JkPIbhMcYMeoT9Q5oGt28ggDsUiWLvCL81YTqCZMzAbVCGLUPrDHouda4cELZRujcS7d8rUNcZVl7HxUXdDsOUtc65s2knGbxSo%3D";

		Map<String,String> params = URLUtils.parseParameters(fragment);

		assertEquals("openid email profile", params.get("scope"));
		assertEquals("cVIe4g4D1J3tYtZgnTL-Po9QpozQJdikDCBp7KJorIQ", params.get("state"));
		assertEquals("1nf1ljB0JkPIbhMcYMeoT9Q5oGt28ggDsUiWLvCL81YTqCZMzAbVCGLUPrDHouda4cELZRujcS7d8rUNcZVl7HxUXdDsOUtc65s2knGbxSo=", params.get("code"));
	}


	// See iss #169
	public void testAllowEqualsCharInParamValue() {

		String query = "key0=value&key1=value=&key2=value==&key3=value===";

		Map<String,String> params = URLUtils.parseParameters(query);
		assertEquals("value", params.get("key0"));
		assertEquals("value=", params.get("key1"));
		assertEquals("value==", params.get("key2"));
		assertEquals("value===", params.get("key3"));
		assertEquals(4, params.size());
	}


	public void testSerializeAlt_duplicateKeys() {

		Map<String,String[]> params = new LinkedHashMap<>();

		params.put("fruit", new String[]{"apple", "orange"});
		params.put("veg", new String[]{"lettuce"});

		String s = URLUtils.serializeParametersAlt(params);

		assertEquals("fruit=apple&fruit=orange&veg=lettuce", s);
	}


	public void testSerializeAlt_nullKey() {

		Map<String,String[]> params = new LinkedHashMap<>();

		params.put("fruit", new String[]{"apple", null});
		params.put("veg", new String[]{"lettuce"});

		String s = URLUtils.serializeParametersAlt(params);

		assertEquals("fruit=apple&fruit=&veg=lettuce", s);
	}
}

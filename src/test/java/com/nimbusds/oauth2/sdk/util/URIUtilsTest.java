package com.nimbusds.oauth2.sdk.util;


import java.net.URI;
import java.net.URISyntaxException;

import junit.framework.TestCase;


/**
 * Tests the URI utility methods.
 */
public class URIUtilsTest extends TestCase {


	public void testGetBaseURISame()
		throws URISyntaxException {

		URI uri = new URI("http://client.example.com:8080/endpoints/openid/connect/cb");

		URI baseURI = URIUtils.getBaseURI(uri);

		assertEquals("http://client.example.com:8080/endpoints/openid/connect/cb", baseURI.toString());
	}


	public void testGetBaseURITrim()
		throws URISyntaxException {

		URI uri = new URI("http://client.example.com:8080/endpoints/openid/connect/cb?param1=one&param2=two");

		URI baseURI = URIUtils.getBaseURI(uri);

		assertEquals("http://client.example.com:8080/endpoints/openid/connect/cb", baseURI.toString());
	}
}

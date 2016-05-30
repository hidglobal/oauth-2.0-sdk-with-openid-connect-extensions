package com.nimbusds.openid.connect.sdk.id;


import java.io.IOException;
import java.net.SocketException;
import java.net.URI;
import java.net.URL;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.oauth2.sdk.GeneralException;
import junit.framework.TestCase;
import net.minidev.json.JSONArray;


public class SectorIDURIValidatorTest extends TestCase {
	

	public void testSuccess()
		throws Exception {

		ResourceRetriever resourceRetriever = new ResourceRetriever() {
			@Override
			public Resource retrieveResource(URL url) throws IOException {

				JSONArray jsonArray = new JSONArray();
				jsonArray.add("https://myapp.com/callback");
				jsonArray.add("https://yourapp.com/callback");
				return new Resource(jsonArray.toJSONString(), "application/json");
			}
		};

		SectorIDURIValidator v = new SectorIDURIValidator(resourceRetriever);

		assertEquals(resourceRetriever, v.getResourceRetriever());

		Set<URI> redirectURIs = new HashSet<>(Arrays.asList(URI.create("https://myapp.com/callback"), URI.create("https://yourapp.com/callback")));

		v.validate(URI.create("https://example.com/apps.json"), redirectURIs);
	}


	public void testRetrievalFailed()
		throws Exception {

		ResourceRetriever resourceRetriever = new ResourceRetriever() {
			@Override
			public Resource retrieveResource(URL url) throws IOException {

				throw new SocketException("Timeout");
			}
		};

		SectorIDURIValidator v = new SectorIDURIValidator(resourceRetriever);

		assertEquals(resourceRetriever, v.getResourceRetriever());

		Set<URI> redirectURIs = new HashSet<>(Arrays.asList(URI.create("https://myapp.com/callback"), URI.create("https://yourapp.com/callback")));

		try {
			v.validate(URI.create("https://example.com/apps.json"), redirectURIs);
			fail();
		} catch (GeneralException e) {
			assertEquals("Couldn't retrieve the sector ID JSON document: Timeout", e.getMessage());
		}
	}


	public void testMissingContentType()
		throws Exception {

		ResourceRetriever resourceRetriever = new ResourceRetriever() {
			@Override
			public Resource retrieveResource(URL url) throws IOException {

				JSONArray jsonArray = new JSONArray();
				jsonArray.add("https://myapp.com/callback");
				jsonArray.add("https://yourapp.com/callback");
				return new Resource(jsonArray.toJSONString(), null);
			}
		};

		SectorIDURIValidator v = new SectorIDURIValidator(resourceRetriever);

		assertEquals(resourceRetriever, v.getResourceRetriever());

		Set<URI> redirectURIs = new HashSet<>(Arrays.asList(URI.create("https://myapp.com/callback"), URI.create("https://yourapp.com/callback")));

		try {
			v.validate(URI.create("https://example.com/apps.json"), redirectURIs);
			fail();
		} catch (GeneralException e) {
			assertEquals("Couldn't validate sector ID URI: Missing Content-Type", e.getMessage());
		}
	}


	public void testBadContentType()
		throws Exception {

		ResourceRetriever resourceRetriever = new ResourceRetriever() {
			@Override
			public Resource retrieveResource(URL url) throws IOException {

				JSONArray jsonArray = new JSONArray();
				jsonArray.add("https://myapp.com/callback");
				jsonArray.add("https://yourapp.com/callback");
				return new Resource(jsonArray.toJSONString(), "text/plain");
			}
		};

		SectorIDURIValidator v = new SectorIDURIValidator(resourceRetriever);

		assertEquals(resourceRetriever, v.getResourceRetriever());

		Set<URI> redirectURIs = new HashSet<>(Arrays.asList(URI.create("https://myapp.com/callback"), URI.create("https://yourapp.com/callback")));

		try {
			v.validate(URI.create("https://example.com/apps.json"), redirectURIs);
			fail();
		} catch (GeneralException e) {
			assertEquals("Couldn't validate sector ID URI: Content-Type must be application/json, found text/plain", e.getMessage());
		}
	}


	public void testBadJSON()
		throws Exception {

		ResourceRetriever resourceRetriever = new ResourceRetriever() {
			@Override
			public Resource retrieveResource(URL url) throws IOException {

				return new Resource("a b c", "application/json");
			}
		};

		SectorIDURIValidator v = new SectorIDURIValidator(resourceRetriever);

		assertEquals(resourceRetriever, v.getResourceRetriever());

		Set<URI> redirectURIs = new HashSet<>(Arrays.asList(URI.create("https://myapp.com/callback"), URI.create("https://yourapp.com/callback")));

		try {
			v.validate(URI.create("https://example.com/apps.json"), redirectURIs);
			fail();
		} catch (GeneralException e) {
			assertEquals("Invalid JSON: Unexpected token a b c at position 5.", e.getMessage());
		}
	}


	public void testRedirectURINotFoundInSectorIDURI()
		throws Exception {

		ResourceRetriever resourceRetriever = new ResourceRetriever() {
			@Override
			public Resource retrieveResource(URL url) throws IOException {

				JSONArray jsonArray = new JSONArray();
				jsonArray.add("https://myapp.com/callback");
				return new Resource(jsonArray.toJSONString(), "application/json");
			}
		};

		SectorIDURIValidator v = new SectorIDURIValidator(resourceRetriever);

		assertEquals(resourceRetriever, v.getResourceRetriever());

		Set<URI> redirectURIs = new HashSet<>(Arrays.asList(URI.create("https://myapp.com/callback"), URI.create("https://yourapp.com/callback")));

		try {
			v.validate(URI.create("https://example.com/apps.json"), redirectURIs);
			fail();
		} catch (GeneralException e) {
			assertEquals("Sector ID URI validation failed: Redirect URI https://yourapp.com/callback is missing from published JSON array at sector ID URI https://example.com/apps.json", e.getMessage());
		}
	}
}

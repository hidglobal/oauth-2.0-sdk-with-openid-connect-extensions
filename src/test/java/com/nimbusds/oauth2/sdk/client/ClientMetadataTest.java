package com.nimbusds.oauth2.sdk.client;


import java.net.URL;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.mail.internet.InternetAddress;

import junit.framework.TestCase;

import net.minidev.json.JSONObject;

import com.nimbusds.langtag.LangTag;

import com.nimbusds.oauth2.sdk.id.SoftwareID;
import com.nimbusds.oauth2.sdk.id.SoftwareVersion;

import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * Tests the OAuth 2.0 client metadata class.
 */
public class ClientMetadataTest extends TestCase {


	public void testRegisteredParameters() {

		Set<String> paramNames = ClientMetadata.getRegisteredParameterNames();

		assertTrue(paramNames.contains("redirect_uris"));
		assertTrue(paramNames.contains("client_name"));
		assertTrue(paramNames.contains("client_uri"));
		assertTrue(paramNames.contains("logo_uri"));
		assertTrue(paramNames.contains("contacts"));
		assertTrue(paramNames.contains("tos_uri"));
		assertTrue(paramNames.contains("policy_uri"));
		assertTrue(paramNames.contains("token_endpoint_auth_method"));
		assertTrue(paramNames.contains("scope"));
		assertTrue(paramNames.contains("grant_types"));
		assertTrue(paramNames.contains("response_types"));
		assertTrue(paramNames.contains("jwks_uri"));
		assertTrue(paramNames.contains("software_id"));
		assertTrue(paramNames.contains("software_version"));

		assertEquals(14, ClientMetadata.getRegisteredParameterNames().size());
	}
	
	
	public void testSerializeAndParse()
		throws Exception {
		
		ClientMetadata meta = new ClientMetadata();
		
		Set<URL> redirectURIs = new HashSet<URL>();
		redirectURIs.add(new URL("http://example.com/1"));
		redirectURIs.add(new URL("http://example.com/2"));
		meta.setRedirectionURIs(redirectURIs);
		
		Scope scope = Scope.parse("read write");
		meta.setScope(scope);
		
		Set<ResponseType> rts = new HashSet<ResponseType>();
		rts.add(ResponseType.parse("code id_token"));
		meta.setResponseTypes(rts);
		
		Set<GrantType> grantTypes = new HashSet<GrantType>();
		grantTypes.add(GrantType.AUTHORIZATION_CODE);
		grantTypes.add(GrantType.REFRESH_TOKEN);
		meta.setGrantTypes(grantTypes);
		
		List<InternetAddress> contacts = new LinkedList<InternetAddress>();
		contacts.add(new InternetAddress("alice@wonderland.net"));
		contacts.add(new InternetAddress("admin@wonderland.net"));
		meta.setContacts(contacts);
		
		String name = "My Example App";
		meta.setName(name);
		
		String nameDE = "Mein Beispiel App";
		meta.setName(nameDE, LangTag.parse("de"));
		
		URL logo = new URL("http://example.com/logo.png");
		meta.setLogoURI(logo);
		
		URL logoDE = new URL("http://example.com/de/logo.png");
		meta.setLogoURI(logoDE, LangTag.parse("de"));
		
		URL uri = new URL("http://example.com");
		meta.setURI(uri);
		
		URL uriDE = new URL("http://example.com/de");
		meta.setURI(uriDE, LangTag.parse("de"));
		
		URL policy = new URL("http://example.com/policy");
		meta.setPolicyURI(policy);
		
		URL policyDE = new URL("http://example.com/de/policy");
		meta.setPolicyURI(policyDE, LangTag.parse("de"));
		
		URL tos = new URL("http://example.com/tos");
		meta.setTermsOfServiceURI(tos);
		
		URL tosDE = new URL("http://example.com/de/tos");
		meta.setTermsOfServiceURI(tosDE, LangTag.parse("de"));
		
		ClientAuthenticationMethod authMethod = ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
		meta.setTokenEndpointAuthMethod(authMethod);
		
		URL jwks = new URL("http://example.com/jwks.json");
		meta.setJWKSetURL(jwks);

		SoftwareID softwareID = new SoftwareID();
		meta.setSoftwareID(softwareID);

		SoftwareVersion softwareVersion = new SoftwareVersion("1.0");
		meta.setSoftwareVersion(softwareVersion);
		
		// Test getters
		assertEquals(redirectURIs, meta.getRedirectionURIs());
		assertEquals(scope, meta.getScope());
		assertEquals(grantTypes, meta.getGrantTypes());
		assertEquals(contacts, meta.getContacts());
		assertEquals(name, meta.getName());
		assertEquals(nameDE, meta.getName(LangTag.parse("de")));
		assertEquals(2, meta.getNameEntries().size());
		assertEquals(logo, meta.getLogoURI());
		assertEquals(logoDE, meta.getLogoURI(LangTag.parse("de")));
		assertEquals(2, meta.getLogoURIEntries().size());
		assertEquals(uri, meta.getURI());
		assertEquals(uriDE, meta.getURI(LangTag.parse("de")));
		assertEquals(2, meta.getURIEntries().size());
		assertEquals(policy, meta.getPolicyURI());
		assertEquals(policyDE, meta.getPolicyURI(LangTag.parse("de")));
		assertEquals(2, meta.getPolicyURIEntries().size());
		assertEquals(tos, meta.getTermsOfServiceURI());
		assertEquals(tosDE, meta.getTermsOfServiceURI(LangTag.parse("de")));
		assertEquals(2, meta.getTermsOfServiceURIEntries().size());
		assertEquals(authMethod, meta.getTokenEndpointAuthMethod());
		assertEquals(jwks, meta.getJWKSetURI());
		assertEquals(softwareID, meta.getSoftwareID());
		assertEquals(softwareVersion, meta.getSoftwareVersion());
		assertTrue(meta.getCustomFields().isEmpty());
		
		String json = meta.toJSONObject().toJSONString();
		
		System.out.println("OAuth 2.0 client metadata: " + json);
		
		JSONObject jsonObject = JSONObjectUtils.parseJSONObject(json);
		
		
		meta = ClientMetadata.parse(jsonObject);
		
		// Test getters
		assertEquals(redirectURIs, meta.getRedirectionURIs());
		assertEquals(scope, meta.getScope());
		assertEquals(grantTypes, meta.getGrantTypes());
		assertEquals(contacts, meta.getContacts());
		assertEquals(name, meta.getName());
		assertEquals(nameDE, meta.getName(LangTag.parse("de")));
		assertEquals(2, meta.getNameEntries().size());
		assertEquals(logo, meta.getLogoURI());
		assertEquals(logoDE, meta.getLogoURI(LangTag.parse("de")));
		assertEquals(2, meta.getLogoURIEntries().size());
		assertEquals(uri, meta.getURI());
		assertEquals(uriDE, meta.getURI(LangTag.parse("de")));
		assertEquals(2, meta.getURIEntries().size());
		assertEquals(policy, meta.getPolicyURI());
		assertEquals(policyDE, meta.getPolicyURI(LangTag.parse("de")));
		assertEquals(2, meta.getPolicyURIEntries().size());
		assertEquals(tos, meta.getTermsOfServiceURI());
		assertEquals(tosDE, meta.getTermsOfServiceURI(LangTag.parse("de")));
		assertEquals(2, meta.getTermsOfServiceURIEntries().size());
		assertEquals(authMethod, meta.getTokenEndpointAuthMethod());
		assertEquals(jwks, meta.getJWKSetURI());
		assertEquals(softwareID, meta.getSoftwareID());
		assertEquals(softwareVersion, meta.getSoftwareVersion());

		System.out.println("Meta custom fields: " + meta.getCustomFields());

		assertTrue(meta.getCustomFields().isEmpty());
	}


	public void testApplyDefaults() 
		throws Exception {
		
		ClientMetadata meta = new ClientMetadata();
		
		assertNull(meta.getResponseTypes());
		assertNull(meta.getGrantTypes());
		assertNull(meta.getTokenEndpointAuthMethod());
		
		meta.applyDefaults();
		
		Set<ResponseType> rts = meta.getResponseTypes();
		assertTrue(rts.contains(ResponseType.parse("code")));
		
		Set<GrantType> grantTypes = meta.getGrantTypes();
		assertTrue(grantTypes.contains(GrantType.AUTHORIZATION_CODE));
		
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, meta.getTokenEndpointAuthMethod());
	}


	public void testCustomFields()
		throws Exception {

		ClientMetadata meta = new ClientMetadata();

		meta.setCustomField("x-data", "123");

		assertEquals("123", (String)meta.getCustomField("x-data"));
		assertEquals("123", (String)meta.getCustomFields().get("x-data"));
		assertEquals(1, meta.getCustomFields().size());

		String json = meta.toJSONObject().toJSONString();

		meta = ClientMetadata.parse(JSONObjectUtils.parseJSONObject(json));

		assertEquals("123", (String)meta.getCustomField("x-data"));
		assertEquals("123", (String)meta.getCustomFields().get("x-data"));
		assertEquals(1, meta.getCustomFields().size());
	}


	public void testSetSingleRedirectURI()
		throws Exception {

		ClientMetadata meta = new ClientMetadata();

		URL uri = new URL("https://client.com/callback");

		meta.setRedirectionURI(uri);

		assertTrue(meta.getRedirectionURIs().contains(uri));
		assertEquals(1, meta.getRedirectionURIs().size());

		meta.setRedirectionURI(null);
		assertNull(meta.getRedirectionURIs());
	}
}
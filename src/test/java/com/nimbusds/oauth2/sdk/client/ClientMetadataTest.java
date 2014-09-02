package com.nimbusds.oauth2.sdk.client;


import java.net.URI;
import java.util.*;

import javax.mail.internet.InternetAddress;

import junit.framework.TestCase;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;

import com.nimbusds.langtag.LangTag;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.id.SoftwareID;
import com.nimbusds.oauth2.sdk.id.SoftwareVersion;
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
		assertTrue(paramNames.contains("jwks"));
		assertTrue(paramNames.contains("software_id"));
		assertTrue(paramNames.contains("software_version"));

		assertEquals(15, ClientMetadata.getRegisteredParameterNames().size());
	}
	
	
	public void testSerializeAndParse()
		throws Exception {
		
		ClientMetadata meta = new ClientMetadata();
		
		Set<URI> redirectURIs = new HashSet<>();
		redirectURIs.add(new URI("http://example.com/1"));
		redirectURIs.add(new URI("http://example.com/2"));
		meta.setRedirectionURIs(redirectURIs);
		
		Scope scope = Scope.parse("read write");
		meta.setScope(scope);
		
		Set<ResponseType> rts = new HashSet<>();
		rts.add(ResponseType.parse("code id_token"));
		meta.setResponseTypes(rts);
		
		Set<GrantType> grantTypes = new HashSet<>();
		grantTypes.add(GrantType.AUTHORIZATION_CODE);
		grantTypes.add(GrantType.REFRESH_TOKEN);
		meta.setGrantTypes(grantTypes);
		
		List<InternetAddress> contacts = new LinkedList<>();
		contacts.add(new InternetAddress("alice@wonderland.net"));
		contacts.add(new InternetAddress("admin@wonderland.net"));
		meta.setContacts(contacts);
		
		String name = "My Example App";
		meta.setName(name);
		
		String nameDE = "Mein Beispiel App";
		meta.setName(nameDE, LangTag.parse("de"));
		
		URI logo = new URI("http://example.com/logo.png");
		meta.setLogoURI(logo);
		
		URI logoDE = new URI("http://example.com/de/logo.png");
		meta.setLogoURI(logoDE, LangTag.parse("de"));
		
		URI uri = new URI("http://example.com");
		meta.setURI(uri);
		
		URI uriDE = new URI("http://example.com/de");
		meta.setURI(uriDE, LangTag.parse("de"));
		
		URI policy = new URI("http://example.com/policy");
		meta.setPolicyURI(policy);
		
		URI policyDE = new URI("http://example.com/de/policy");
		meta.setPolicyURI(policyDE, LangTag.parse("de"));
		
		URI tos = new URI("http://example.com/tos");
		meta.setTermsOfServiceURI(tos);
		
		URI tosDE = new URI("http://example.com/de/tos");
		meta.setTermsOfServiceURI(tosDE, LangTag.parse("de"));
		
		ClientAuthenticationMethod authMethod = ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
		meta.setTokenEndpointAuthMethod(authMethod);
		
		URI jwksURI = new URI("http://example.com/jwks.json");
		meta.setJWKSetURI(jwksURI);

		RSAKey rsaKey = new RSAKey.Builder(new Base64URL("nabc"), new Base64URL("eabc")).build();
		JWKSet jwkSet = new JWKSet(rsaKey);
		meta.setJWKSet(jwkSet);

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
		assertEquals(jwksURI, meta.getJWKSetURI());
		assertEquals("nabc", ((RSAKey)meta.getJWKSet().getKeys().get(0)).getModulus().toString());
		assertEquals("eabc", ((RSAKey)meta.getJWKSet().getKeys().get(0)).getPublicExponent().toString());
		assertEquals(1, meta.getJWKSet().getKeys().size());
		assertEquals(softwareID, meta.getSoftwareID());
		assertEquals(softwareVersion, meta.getSoftwareVersion());
		assertTrue(meta.getCustomFields().isEmpty());
		
		String json = meta.toJSONObject().toJSONString();
		
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
		assertEquals(jwksURI, meta.getJWKSetURI());
		assertEquals("nabc", ((RSAKey)meta.getJWKSet().getKeys().get(0)).getModulus().toString());
		assertEquals("eabc", ((RSAKey)meta.getJWKSet().getKeys().get(0)).getPublicExponent().toString());
		assertEquals(1, meta.getJWKSet().getKeys().size());
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

		URI uri = new URI("https://client.com/callback");

		meta.setRedirectionURI(uri);

		assertTrue(meta.getRedirectionURIs().contains(uri));
		assertEquals(1, meta.getRedirectionURIs().size());

		meta.setRedirectionURI(null);
		assertNull(meta.getRedirectionURIs());
	}


	public void testGetRedirectionURIStrings()
		throws Exception {

		ClientMetadata meta = new ClientMetadata();

		assertNull(meta.getRedirectionURIStrings());

		Set<URI> redirectURIs = new HashSet<>();
		redirectURIs.add(new URI("https://cliemt.com/cb-1"));
		redirectURIs.add(new URI("https://cliemt.com/cb-2"));
		redirectURIs.add(new URI("https://cliemt.com/cb-3"));

		meta.setRedirectionURIs(redirectURIs);

		assertTrue(meta.getRedirectionURIStrings().contains("https://cliemt.com/cb-1"));
		assertTrue(meta.getRedirectionURIStrings().contains("https://cliemt.com/cb-2"));
		assertTrue(meta.getRedirectionURIStrings().contains("https://cliemt.com/cb-3"));
		assertEquals(3, meta.getRedirectionURIStrings().size());

		meta.setRedirectionURI(new URI("https://cliemt.com/cb"));
		assertTrue(meta.getRedirectionURIStrings().contains("https://cliemt.com/cb"));
		assertEquals(1, meta.getRedirectionURIStrings().size());
	}


	public void testParse()
		throws Exception {

		String json = "{\n" +
			"      \"redirect_uris\":[\n" +
			"        \"https://client.example.org/callback\",\n" +
			"        \"https://client.example.org/callback2\"],\n" +
			"      \"token_endpoint_auth_method\":\"client_secret_basic\",\n" +
			"      \"example_extension_parameter\": \"example_value\"\n" +
			"     }";

		ClientMetadata meta = ClientMetadata.parse(JSONObjectUtils.parseJSONObject(json));

		assertTrue(meta.getRedirectionURIs().contains(new URI("https://client.example.org/callback")));
		assertTrue(meta.getRedirectionURIs().contains(new URI("https://client.example.org/callback2")));
		assertEquals(2, meta.getRedirectionURIs().size());

		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, meta.getTokenEndpointAuthMethod());

		assertEquals("example_value", meta.getCustomField("example_extension_parameter"));
	}


	public void testParseBadRedirectionURI()
		throws Exception {

		String json = "{\n" +
			" \"redirect_uris\":[\n" +
			"   \"https://\",\n" +
			"   \"https://client.example.org/callback2\"],\n" +
			" \"token_endpoint_auth_method\":\"client_secret_basic\",\n" +
			" \"example_extension_parameter\": \"example_value\"\n" +
			"}";

		try {
			ClientMetadata.parse(JSONObjectUtils.parseJSONObject(json));
			fail();
		} catch (ParseException e) {
			// ok
		}
	}


	public void testClientCredentialsGrant()
		throws Exception {

		JSONObject o = new JSONObject();
		o.put("client_name", "Test App");
		o.put("grant_types", Arrays.asList("client_credentials"));
		o.put("response_types", new ArrayList<String>());
		o.put("scope", "read write");

		String json = o.toJSONString();

		ClientMetadata metadata = ClientMetadata.parse(JSONObjectUtils.parseJSONObject(json));

		assertEquals("Test App", metadata.getName());
		assertTrue(metadata.getGrantTypes().contains(GrantType.CLIENT_CREDENTIALS));
		assertEquals(1, metadata.getGrantTypes().size());
		assertTrue(metadata.getResponseTypes().isEmpty());
		assertTrue(Scope.parse("read write").containsAll(metadata.getScope()));
		assertEquals(2, metadata.getScope().size());

		assertNull(metadata.getTokenEndpointAuthMethod());

		metadata.applyDefaults();

		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, metadata.getTokenEndpointAuthMethod());
	}


	public void testPasswordGrant()
		throws Exception {

		JSONObject o = new JSONObject();
		o.put("client_name", "Test App");
		o.put("grant_types", Arrays.asList("password"));
		o.put("response_types", new ArrayList<String>());
		o.put("scope", "read write");

		String json = o.toJSONString();

		ClientMetadata metadata = ClientMetadata.parse(JSONObjectUtils.parseJSONObject(json));

		assertEquals("Test App", metadata.getName());
		assertTrue(metadata.getGrantTypes().contains(GrantType.PASSWORD));
		assertEquals(1, metadata.getGrantTypes().size());
		assertTrue(metadata.getResponseTypes().isEmpty());
		assertTrue(Scope.parse("read write").containsAll(metadata.getScope()));
		assertEquals(2, metadata.getScope().size());

		assertNull(metadata.getTokenEndpointAuthMethod());

		metadata.applyDefaults();

		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, metadata.getTokenEndpointAuthMethod());
	}
}
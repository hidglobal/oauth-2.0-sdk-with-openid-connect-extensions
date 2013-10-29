package com.nimbusds.openid.connect.sdk.op;


import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import com.nimbusds.oauth2.sdk.ParseException;
import junit.framework.TestCase;

import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.id.Issuer;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;

import com.nimbusds.openid.connect.sdk.Display;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.ClaimType;
import net.minidev.json.JSONObject;


/**
 * Tests the OIDC provider metadata class.
 *
 * @author Vladimir Dzhuvinov
 */
public class OIDCProviderMetadataTest extends TestCase {


	public void testRegisteredParameters() {

		Set<String> paramNames = OIDCProviderMetadata.getRegisteredParameterNames();

		assertTrue(paramNames.contains("issuer"));
		assertTrue(paramNames.contains("authorization_endpoint"));
		assertTrue(paramNames.contains("token_endpoint"));
		assertTrue(paramNames.contains("userinfo_endpoint"));
		assertTrue(paramNames.contains("jwks_uri"));
		assertTrue(paramNames.contains("registration_endpoint"));
		assertTrue(paramNames.contains("scopes_supported"));
		assertTrue(paramNames.contains("response_types_supported"));
		assertTrue(paramNames.contains("response_modes_supported"));
		assertTrue(paramNames.contains("grant_types_supported"));
		assertTrue(paramNames.contains("acr_values_supported"));
		assertTrue(paramNames.contains("subject_types_supported"));
		assertTrue(paramNames.contains("id_token_signing_alg_values_supported"));
		assertTrue(paramNames.contains("id_token_encryption_alg_values_supported"));
		assertTrue(paramNames.contains("id_token_encryption_enc_values_supported"));
		assertTrue(paramNames.contains("userinfo_signing_alg_values_supported"));
		assertTrue(paramNames.contains("userinfo_encryption_alg_values_supported"));
		assertTrue(paramNames.contains("userinfo_encryption_enc_values_supported"));
		assertTrue(paramNames.contains("request_object_signing_alg_values_supported"));
		assertTrue(paramNames.contains("request_object_encryption_alg_values_supported"));
		assertTrue(paramNames.contains("request_object_encryption_enc_values_supported"));
		assertTrue(paramNames.contains("token_endpoint_auth_methods_supported"));
		assertTrue(paramNames.contains("token_endpoint_auth_signing_alg_values_supported"));
		assertTrue(paramNames.contains("display_values_supported"));
		assertTrue(paramNames.contains("claim_types_supported"));
		assertTrue(paramNames.contains("claims_supported"));
		assertTrue(paramNames.contains("service_documentation"));
		assertTrue(paramNames.contains("claims_locales_supported"));
		assertTrue(paramNames.contains("ui_locales_supported"));
		assertTrue(paramNames.contains("claims_parameter_supported"));
		assertTrue(paramNames.contains("request_parameter_supported"));
		assertTrue(paramNames.contains("request_uri_parameter_supported"));
		assertTrue(paramNames.contains("require_request_uri_registration"));
		assertTrue(paramNames.contains("op_policy_uri"));
		assertTrue(paramNames.contains("op_tos_uri"));
		assertTrue(paramNames.contains("check_session_iframe"));
		assertTrue(paramNames.contains("end_session_endpoint"));

		assertEquals(37, paramNames.size());
	}


	public void testParseExample() throws Exception {

		String s = "{\n" +
			"   \"issuer\":\n" +
			"     \"https://server.example.com\",\n" +
			"   \"authorization_endpoint\":\n" +
			"     \"https://server.example.com/connect/authorize\",\n" +
			"   \"token_endpoint\":\n" +
			"     \"https://server.example.com/connect/token\",\n" +
			"   \"token_endpoint_auth_methods_supported\":\n" +
			"     [\"client_secret_basic\", \"private_key_jwt\"],\n" +
			"   \"token_endpoint_auth_signing_alg_values_supported\":\n" +
			"     [\"RS256\", \"ES256\"],\n" +
			"   \"userinfo_endpoint\":\n" +
			"     \"https://server.example.com/connect/userinfo\",\n" +
			"   \"check_session_iframe\":\n" +
			"     \"https://server.example.com/connect/check_session\",\n" +
			"   \"end_session_endpoint\":\n" +
			"     \"https://server.example.com/connect/end_session\",\n" +
			"   \"jwks_uri\":\n" +
			"     \"https://server.example.com/jwks.json\",\n" +
			"   \"registration_endpoint\":\n" +
			"     \"https://server.example.com/connect/register\",\n" +
			"   \"scopes_supported\":\n" +
			"     [\"openid\", \"profile\", \"email\", \"address\",\n" +
			"      \"phone\", \"offline_access\"],\n" +
			"   \"response_types_supported\":\n" +
			"     [\"code\", \"code id_token\", \"id_token\", \"token id_token\"],\n" +
			"   \"acr_values_supported\":\n" +
			"     [\"urn:mace:incommon:iap:silver\",\n" +
			"      \"urn:mace:incommon:iap:bronze\"],\n" +
			"   \"subject_types_supported\":\n" +
			"     [\"public\", \"pairwise\"],\n" +
			"   \"userinfo_signing_alg_values_supported\":\n" +
			"     [\"RS256\", \"ES256\", \"HS256\"],\n" +
			"   \"userinfo_encryption_alg_values_supported\":\n" +
			"     [\"RSA1_5\", \"A128KW\"],\n" +
			"   \"userinfo_encryption_enc_values_supported\":\n" +
			"     [\"A128CBC-HS256\", \"A128GCM\"],\n" +
			"   \"id_token_signing_alg_values_supported\":\n" +
			"     [\"RS256\", \"ES256\", \"HS256\"],\n" +
			"   \"id_token_encryption_alg_values_supported\":\n" +
			"     [\"RSA1_5\", \"A128KW\"],\n" +
			"   \"id_token_encryption_enc_values_supported\":\n" +
			"     [\"A128CBC-HS256\", \"A128GCM\"],\n" +
			"   \"request_object_signing_alg_values_supported\":\n" +
			"     [\"none\", \"RS256\", \"ES256\"],\n" +
			"   \"display_values_supported\":\n" +
			"     [\"page\", \"popup\"],\n" +
			"   \"claim_types_supported\":\n" +
			"     [\"normal\", \"distributed\"],\n" +
			"   \"claims_supported\":\n" +
			"     [\"sub\", \"iss\", \"auth_time\", \"acr\",\n" +
			"      \"name\", \"given_name\", \"family_name\", \"nickname\",\n" +
			"      \"profile\", \"picture\", \"website\",\n" +
			"      \"email\", \"email_verified\", \"locale\", \"zoneinfo\",\n" +
			"      \"http://example.info/claims/groups\"],\n" +
			"   \"claims_parameter_supported\":\n" +
			"     true,\n" +
			"   \"service_documentation\":\n" +
			"     \"http://server.example.com/connect/service_documentation.html\",\n" +
			"   \"ui_locales_supported\":\n" +
			"     [\"en-US\", \"en-GB\", \"en-CA\", \"fr-FR\", \"fr-CA\"]\n" +
			"  }";
		
		OIDCProviderMetadata op = OIDCProviderMetadata.parse(s);
		
		assertEquals("https://server.example.com", op.getIssuer().getValue());
		assertEquals("https://server.example.com/connect/authorize", op.getAuthorizationEndpointURL().toString());
		assertEquals("https://server.example.com/connect/token", op.getTokenEndpointURL().toString());
		
		List<ClientAuthenticationMethod> authMethods = op.getTokenEndpointAuthMethods();
		assertTrue(authMethods.contains(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
		assertTrue(authMethods.contains(ClientAuthenticationMethod.PRIVATE_KEY_JWT));
		assertEquals(2, authMethods.size());
		
		List<JWSAlgorithm> tokenEndpointJWSAlgs = op.getTokenEndpointJWSAlgs();
		assertTrue(tokenEndpointJWSAlgs.contains(JWSAlgorithm.RS256));
		assertTrue(tokenEndpointJWSAlgs.contains(JWSAlgorithm.ES256));
		assertEquals(2, tokenEndpointJWSAlgs.size());
		
		assertEquals("https://server.example.com/connect/userinfo", op.getUserInfoEndpointURL().toString());
		
		assertEquals("https://server.example.com/connect/check_session", op.getCheckSessionIframeURL().toString());
		assertEquals("https://server.example.com/connect/end_session", op.getEndSessionEndpointURL().toString());
		
		assertEquals("https://server.example.com/jwks.json", op.getJWKSetURI().toString());
		
		assertEquals("https://server.example.com/connect/register", op.getRegistrationEndpointURL().toString());
		Scope scopes = op.getScopes();
		assertTrue(scopes.contains(OIDCScopeValue.OPENID));
		assertTrue(scopes.contains(OIDCScopeValue.PROFILE));
		assertTrue(scopes.contains(OIDCScopeValue.EMAIL));
		assertTrue(scopes.contains(OIDCScopeValue.ADDRESS));
		assertTrue(scopes.contains(OIDCScopeValue.PHONE));
		assertTrue(scopes.contains(OIDCScopeValue.OFFLINE_ACCESS));
		assertEquals(6, scopes.size());
		
		List<ResponseType> rts = op.getResponseTypes();
		// [\"code\", \"code id_token\", \"id_token\", \"token id_token\"]
		ResponseType rt1 = new ResponseType();
		rt1.add(ResponseType.Value.CODE);
		assertTrue(rts.contains(rt1));
		
		ResponseType rt2 = new ResponseType();
		rt2.add(ResponseType.Value.CODE);
		rt2.add(OIDCResponseTypeValue.ID_TOKEN);
		assertTrue(rts.contains(rt2));
		
		ResponseType rt3 = new ResponseType();
		rt3.add(OIDCResponseTypeValue.ID_TOKEN);
		assertTrue(rts.contains(rt3));
		
		ResponseType rt4 = new ResponseType();
		rt4.add(ResponseType.Value.TOKEN);
		rt4.add(OIDCResponseTypeValue.ID_TOKEN);
		assertTrue(rts.contains(rt4));
		
		assertEquals(4, rts.size());
		
		List<ACR> acrValues = op.getACRs();
		assertTrue(acrValues.contains(new ACR("urn:mace:incommon:iap:silver")));
		assertTrue(acrValues.contains(new ACR("urn:mace:incommon:iap:bronze")));
		assertEquals(2, acrValues.size());
		
		List<SubjectType> subjectTypes = op.getSubjectTypes();
		assertTrue(subjectTypes.contains(SubjectType.PUBLIC));
		assertTrue(subjectTypes.contains(SubjectType.PAIRWISE));
		assertEquals(2, subjectTypes.size());
		
		// UserInfo
		List<JWSAlgorithm> userInfoJWSAlgs = op.getUserInfoJWSAlgs();
		assertTrue(userInfoJWSAlgs.contains(JWSAlgorithm.RS256));
		assertTrue(userInfoJWSAlgs.contains(JWSAlgorithm.ES256));
		assertTrue(userInfoJWSAlgs.contains(JWSAlgorithm.HS256));
		assertEquals(3, userInfoJWSAlgs.size());
		
		List<JWEAlgorithm> userInfoJWEalgs = op.getUserInfoJWEAlgs();
		assertTrue(userInfoJWEalgs.contains(JWEAlgorithm.RSA1_5));
		assertTrue(userInfoJWEalgs.contains(JWEAlgorithm.A128KW));
		assertEquals(2, userInfoJWEalgs.size());
		
		List<EncryptionMethod> userInfoEncs = op.getUserInfoJWEEncs();
		assertTrue(userInfoEncs.contains(EncryptionMethod.A128CBC_HS256));
		assertTrue(userInfoEncs.contains(EncryptionMethod.A128GCM));
		assertEquals(2, userInfoEncs.size());
	
		// ID token
		List<JWSAlgorithm> idTokenJWSAlgs = op.getIDTokenJWSAlgs();
		assertTrue(idTokenJWSAlgs.contains(JWSAlgorithm.RS256));
		assertTrue(idTokenJWSAlgs.contains(JWSAlgorithm.ES256));
		assertTrue(idTokenJWSAlgs.contains(JWSAlgorithm.HS256));
		assertEquals(3, idTokenJWSAlgs.size());
		
		List<JWEAlgorithm> idTokenJWEAlgs = op.getIDTokenJWEAlgs();
		assertTrue(idTokenJWEAlgs.contains(JWEAlgorithm.RSA1_5));
		assertTrue(idTokenJWEAlgs.contains(JWEAlgorithm.A128KW));
		assertEquals(2, idTokenJWEAlgs.size());
		
		List<EncryptionMethod> idTokenEncs = op.getIDTokenJWEEncs();
		assertTrue(idTokenEncs.contains(EncryptionMethod.A128CBC_HS256));
		assertTrue(idTokenEncs.contains(EncryptionMethod.A128GCM));
		assertEquals(2, idTokenEncs.size());
		
		// Request object
		List<JWSAlgorithm> requestObjectJWSAlgs = op.getRequestObjectJWSAlgs();
		assertTrue(requestObjectJWSAlgs.contains(JWSAlgorithm.NONE));
		assertTrue(requestObjectJWSAlgs.contains(JWSAlgorithm.RS256));
		assertTrue(requestObjectJWSAlgs.contains(JWSAlgorithm.ES256));
		
		List<Display> displayTypes = op.getDisplays();
		assertTrue(displayTypes.contains(Display.PAGE));
		assertTrue(displayTypes.contains(Display.POPUP));
		assertEquals(2, displayTypes.size());
		
		List<ClaimType> claimTypes = op.getClaimTypes();
		assertTrue(claimTypes.contains(ClaimType.NORMAL));
		assertTrue(claimTypes.contains(ClaimType.DISTRIBUTED));
		assertEquals(2, claimTypes.size());
		
		List<String> claims = op.getClaims();
		assertTrue(claims.contains("sub"));
		assertTrue(claims.contains("iss"));
		assertTrue(claims.contains("auth_time"));
		assertTrue(claims.contains("acr"));
		assertTrue(claims.contains("name"));
		assertTrue(claims.contains("given_name"));
		assertTrue(claims.contains("family_name"));
		assertTrue(claims.contains("nickname"));
		assertTrue(claims.contains("profile"));
		assertTrue(claims.contains("picture"));
		assertTrue(claims.contains("website"));
		assertTrue(claims.contains("email"));
		assertTrue(claims.contains("email_verified"));
		assertTrue(claims.contains("locale"));
		assertTrue(claims.contains("zoneinfo"));
		assertTrue(claims.contains("http://example.info/claims/groups"));
		assertEquals(16, claims.size());
		
		assertTrue(op.supportsClaimsParam());
		
		assertEquals("http://server.example.com/connect/service_documentation.html", op.getServiceDocsURL().toString());
		
		List<LangTag> uiLocales = op.getUILocales();
		assertTrue(uiLocales.contains(LangTag.parse("en-US")));
		assertTrue(uiLocales.contains(LangTag.parse("en-GB")));
		assertTrue(uiLocales.contains(LangTag.parse("en-CA")));
		assertTrue(uiLocales.contains(LangTag.parse("fr-FR")));
		assertTrue(uiLocales.contains(LangTag.parse("fr-CA")));
		assertEquals(5, uiLocales.size());
	}


	public void testGettersAndSetters()
		throws Exception {

		Issuer issuer = new Issuer("https://c2id.com");

		List<SubjectType> subjectTypes = new LinkedList<SubjectType>();
		subjectTypes.add(SubjectType.PAIRWISE);
		subjectTypes.add(SubjectType.PUBLIC);

		URL jwkSetURI = new URL("https://c2id.com/jwks.json");

		OIDCProviderMetadata meta = new OIDCProviderMetadata(issuer, subjectTypes, jwkSetURI);

		assertEquals(issuer.getValue(), meta.getIssuer().getValue());
		assertEquals(SubjectType.PAIRWISE, meta.getSubjectTypes().get(0));
		assertEquals(SubjectType.PUBLIC, meta.getSubjectTypes().get(1));
		assertEquals(jwkSetURI.toString(), meta.getJWKSetURI().toString());

		meta.setAuthorizationEndpointURL(new URL("https://c2id.com/authz"));
		assertEquals("https://c2id.com/authz", meta.getAuthorizationEndpointURL().toString());

		meta.setTokenEndpointURL(new URL("https://c2id.com/token"));
		assertEquals("https://c2id.com/token", meta.getTokenEndpointURL().toString());

		meta.setUserInfoEndpointURL(new URL("https://c2id.com/userinfo"));
		assertEquals("https://c2id.com/userinfo", meta.getUserInfoEndpointURL().toString());

		meta.setRegistrationEndpointURL(new URL("https://c2id.com/reg"));
		assertEquals("https://c2id.com/reg", meta.getRegistrationEndpointURL().toString());

		meta.setCheckSessionIframeURL(new URL("https://c2id.com/session"));
		assertEquals("https://c2id.com/session", meta.getCheckSessionIframeURL().toString());

		meta.setEndSessionEndpointURL(new URL("https://c2id.com/logout"));
		assertEquals("https://c2id.com/logout", meta.getEndSessionEndpointURL().toString());

		meta.setScopes(Scope.parse("openid email profile"));
		assertTrue(Scope.parse("openid email profile").containsAll(meta.getScopes()));

		List<ResponseType> responseTypes = new LinkedList<ResponseType>();
		ResponseType rt1 = new ResponseType();
		rt1.add(ResponseType.Value.CODE);
		responseTypes.add(rt1);
		meta.setResponseTypes(responseTypes);
		assertEquals(ResponseType.Value.CODE, responseTypes.iterator().next().iterator().next());
		assertEquals(1, responseTypes.size());

		List<GrantType> grantTypes = new LinkedList<GrantType>();
		grantTypes.add(GrantType.AUTHORIZATION_CODE);
		grantTypes.add(GrantType.REFRESH_TOKEN);
		meta.setGrantTypes(grantTypes);
		assertTrue(meta.getGrantTypes().contains(GrantType.AUTHORIZATION_CODE));
		assertTrue(meta.getGrantTypes().contains(GrantType.REFRESH_TOKEN));

		List<ACR> acrList = new LinkedList<ACR>();
		acrList.add(new ACR("1"));
		meta.setACRs(acrList);
		assertEquals("1", meta.getACRs().get(0).getValue());

		List<ClientAuthenticationMethod> authMethods = new LinkedList<ClientAuthenticationMethod>();
		authMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
		meta.setTokenEndpointAuthMethods(authMethods);
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, meta.getTokenEndpointAuthMethods().get(0));

		List<JWSAlgorithm> tokenEndpointJWSAlgs = new LinkedList<JWSAlgorithm>();
		tokenEndpointJWSAlgs.add(JWSAlgorithm.HS256);
		tokenEndpointJWSAlgs.add(JWSAlgorithm.HS384);
		tokenEndpointJWSAlgs.add(JWSAlgorithm.HS512);
		meta.setTokenEndpointJWSAlgs(tokenEndpointJWSAlgs);
		assertEquals(JWSAlgorithm.HS256, meta.getTokenEndpointJWSAlgs().get(0));
		assertEquals(JWSAlgorithm.HS384, meta.getTokenEndpointJWSAlgs().get(1));
		assertEquals(JWSAlgorithm.HS512, meta.getTokenEndpointJWSAlgs().get(2));

		List<JWSAlgorithm> requestObjectJWSAlgs = new LinkedList<JWSAlgorithm>();
		requestObjectJWSAlgs.add(JWSAlgorithm.HS256);
		meta.setRequestObjectJWSAlgs(requestObjectJWSAlgs);
		assertEquals(JWSAlgorithm.HS256, meta.getRequestObjectJWSAlgs().get(0));

		List<JWEAlgorithm> requestObjectJWEAlgs = new LinkedList<JWEAlgorithm>();
		requestObjectJWEAlgs.add(JWEAlgorithm.A128KW);
		meta.setRequestObjectJWEAlgs(requestObjectJWEAlgs);
		assertEquals(JWEAlgorithm.A128KW, meta.getRequestObjectJWEAlgs().get(0));

		List<EncryptionMethod> requestObjectEncs = new LinkedList<EncryptionMethod>();
		requestObjectEncs.add(EncryptionMethod.A128GCM);
		meta.setRequestObjectJWEEncs(requestObjectEncs);
		assertEquals(EncryptionMethod.A128GCM, meta.getRequestObjectJWEEncs().get(0));

		List<JWSAlgorithm> idTokenJWSAlgs = new LinkedList<JWSAlgorithm>();
		idTokenJWSAlgs.add(JWSAlgorithm.RS256);
		meta.setIdTokenJWSAlgs(idTokenJWSAlgs);
		assertEquals(JWSAlgorithm.RS256, meta.getIDTokenJWSAlgs().get(0));

		List<JWEAlgorithm> idTokenJWEalgs = new LinkedList<JWEAlgorithm>();
		idTokenJWEalgs.add(JWEAlgorithm.A256KW);
		meta.setIDTokenJWEAlgs(idTokenJWEalgs);

		List<EncryptionMethod> idTokenEncs = new LinkedList<EncryptionMethod>();
		idTokenEncs.add(EncryptionMethod.A128GCM);
		meta.setIdTokenJWEEncs(idTokenEncs);
		assertEquals(EncryptionMethod.A128GCM, meta.getIDTokenJWEEncs().get(0));

		List<JWSAlgorithm> userInfoJWSAlgs = new LinkedList<JWSAlgorithm>();
		userInfoJWSAlgs.add(JWSAlgorithm.RS256);
		meta.setUserInfoJWSAlgs(userInfoJWSAlgs);
		assertEquals(JWSAlgorithm.RS256, meta.getUserInfoJWSAlgs().get(0));

		List<JWEAlgorithm> userInfoJWEAlgs = new LinkedList<JWEAlgorithm>();
		userInfoJWEAlgs.add(JWEAlgorithm.RSA1_5);
		meta.setUserInfoJWEAlgs(userInfoJWEAlgs);
		assertEquals(JWEAlgorithm.RSA1_5, meta.getUserInfoJWEAlgs().get(0));

		List<EncryptionMethod> userInfoEncs = new LinkedList<EncryptionMethod>();
		userInfoEncs.add(EncryptionMethod.A128CBC_HS256);
		meta.setUserInfoJWEEncs(userInfoEncs);
		assertEquals(EncryptionMethod.A128CBC_HS256, meta.getUserInfoJWEEncs().get(0));

		List<Display> displays = new LinkedList<Display>();
		displays.add(Display.PAGE);
		displays.add(Display.POPUP);
		meta.setDisplays(displays);
		assertEquals(Display.PAGE, meta.getDisplays().get(0));
		assertEquals(Display.POPUP, meta.getDisplays().get(1));
		assertEquals(2, meta.getDisplays().size());

		List<ClaimType> claimTypes = new LinkedList<ClaimType>();
		claimTypes.add(ClaimType.NORMAL);
		meta.setClaimTypes(claimTypes);
		assertEquals(ClaimType.NORMAL, meta.getClaimTypes().get(0));

		List<String> claims = new LinkedList<String>();
		claims.add("name");
		claims.add("email");
		meta.setClaims(claims);
		assertEquals("name", meta.getClaims().get(0));
		assertEquals("email", meta.getClaims().get(1));
		assertEquals(2, meta.getClaims().size());

		List<LangTag> claimLocales = new LinkedList<LangTag>();
		claimLocales.add(LangTag.parse("en-GB"));
		meta.setClaimLocales(claimLocales);
		assertEquals("en-GB", meta.getClaimsLocales().get(0).toString());

		List<LangTag> uiLocales = new LinkedList<LangTag>();
		uiLocales.add(LangTag.parse("bg-BG"));
		meta.setUILocales(uiLocales);
		assertEquals("bg-BG", meta.getUILocales().get(0).toString());

		meta.setServiceDocsURL(new URL("https://c2id.com/docs"));
		assertEquals("https://c2id.com/docs", meta.getServiceDocsURL().toString());

		meta.setPolicyURI(new URL("https://c2id.com/policy"));
		assertEquals("https://c2id.com/policy", meta.getPolicyURI().toString());

		meta.setTermsOfServiceURI(new URL("https://c2id.com/tos"));
		assertEquals("https://c2id.com/tos", meta.getTermsOfServiceURI().toString());

		meta.setSupportsClaimsParams(true);
		assertTrue(meta.supportsClaimsParam());

		meta.setSupportsRequestParam(true);
		assertTrue(meta.supportsRequestParam());

		meta.setSupportsRequestURIParam(true);
		assertTrue(meta.supportsRequestURIParam());

		meta.setRequiresRequestURIRegistration(true);
		assertTrue(meta.requiresRequestURIRegistration());

		String json = meta.toJSONObject().toJSONString();

		meta = OIDCProviderMetadata.parse(JSONObjectUtils.parseJSONObject(json));

		assertEquals(issuer.getValue(), meta.getIssuer().getValue());
		assertEquals(SubjectType.PAIRWISE, meta.getSubjectTypes().get(0));
		assertEquals(SubjectType.PUBLIC, meta.getSubjectTypes().get(1));
		assertEquals(jwkSetURI.toString(), meta.getJWKSetURI().toString());

		assertEquals("https://c2id.com/authz", meta.getAuthorizationEndpointURL().toString());
		assertEquals("https://c2id.com/token", meta.getTokenEndpointURL().toString());
		assertEquals("https://c2id.com/userinfo", meta.getUserInfoEndpointURL().toString());
		assertEquals("https://c2id.com/reg", meta.getRegistrationEndpointURL().toString());
		assertEquals("https://c2id.com/session", meta.getCheckSessionIframeURL().toString());
		assertEquals("https://c2id.com/logout", meta.getEndSessionEndpointURL().toString());

		assertTrue(Scope.parse("openid email profile").containsAll(meta.getScopes()));

		assertEquals(ResponseType.Value.CODE, responseTypes.iterator().next().iterator().next());
		assertEquals(1, responseTypes.size());

		assertTrue(meta.getGrantTypes().contains(GrantType.AUTHORIZATION_CODE));
		assertTrue(meta.getGrantTypes().contains(GrantType.REFRESH_TOKEN));

		assertEquals("1", meta.getACRs().get(0).getValue());

		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, meta.getTokenEndpointAuthMethods().get(0));

		assertEquals(JWSAlgorithm.HS256, meta.getTokenEndpointJWSAlgs().get(0));
		assertEquals(JWSAlgorithm.HS384, meta.getTokenEndpointJWSAlgs().get(1));
		assertEquals(JWSAlgorithm.HS512, meta.getTokenEndpointJWSAlgs().get(2));

		assertEquals(JWSAlgorithm.HS256, meta.getRequestObjectJWSAlgs().get(0));

		assertEquals(JWEAlgorithm.A128KW, meta.getRequestObjectJWEAlgs().get(0));

		assertEquals(EncryptionMethod.A128GCM, meta.getRequestObjectJWEEncs().get(0));

		assertEquals(JWSAlgorithm.RS256, meta.getIDTokenJWSAlgs().get(0));

		assertEquals(EncryptionMethod.A128GCM, meta.getIDTokenJWEEncs().get(0));

		assertEquals(JWSAlgorithm.RS256, meta.getUserInfoJWSAlgs().get(0));

		assertEquals(JWEAlgorithm.RSA1_5, meta.getUserInfoJWEAlgs().get(0));

		assertEquals(EncryptionMethod.A128CBC_HS256, meta.getUserInfoJWEEncs().get(0));

		assertEquals(Display.PAGE, meta.getDisplays().get(0));
		assertEquals(Display.POPUP, meta.getDisplays().get(1));
		assertEquals(2, meta.getDisplays().size());

		assertEquals(ClaimType.NORMAL, meta.getClaimTypes().get(0));

		assertEquals("name", meta.getClaims().get(0));
		assertEquals("email", meta.getClaims().get(1));
		assertEquals(2, meta.getClaims().size());

		assertEquals("en-GB", meta.getClaimsLocales().get(0).toString());

		assertEquals("bg-BG", meta.getUILocales().get(0).toString());

		assertEquals("https://c2id.com/docs", meta.getServiceDocsURL().toString());

		assertEquals("https://c2id.com/policy", meta.getPolicyURI().toString());

		assertEquals("https://c2id.com/tos", meta.getTermsOfServiceURI().toString());

		assertTrue(meta.supportsClaimsParam());

		assertTrue(meta.supportsRequestParam());

		assertTrue(meta.supportsRequestURIParam());

		assertTrue(meta.requiresRequestURIRegistration());
	}


	public void testRejectNoneAlgForTokenJWTAuth()
		throws Exception {

		Issuer issuer = new Issuer("https://c2id.com");

		List<SubjectType> subjectTypes = new ArrayList<SubjectType>();
		subjectTypes.add(SubjectType.PUBLIC);

		URL jwksURL = new URL("https://c2id.com/jwks.json");

		OIDCProviderMetadata meta = new OIDCProviderMetadata(issuer, subjectTypes, jwksURL);

		List<JWSAlgorithm> tokenEndpointJWTAlgs = new ArrayList<JWSAlgorithm>();
		tokenEndpointJWTAlgs.add(new JWSAlgorithm("none"));

		try {
			meta.setTokenEndpointJWSAlgs(tokenEndpointJWTAlgs);

			fail("Failed to raise IllegalArgumentException");

		} catch (IllegalArgumentException e) {
			// ok
		}


		// Simulate JSON object with none token endpoint JWT algs
		JSONObject jsonObject = meta.toJSONObject();

		List<String> stringList = new ArrayList<String>();
		stringList.add("none");

		jsonObject.put("token_endpoint_auth_signing_alg_values_supported", stringList);


		try {
			OIDCProviderMetadata.parse(jsonObject.toJSONString());

			fail("Failed to raise ParseException");

		} catch (ParseException e) {
			// ok
		}
	}
}
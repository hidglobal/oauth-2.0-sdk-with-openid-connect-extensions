package com.nimbusds.openid.connect.sdk.op;


import java.util.Set;

import org.junit.Test;
import static org.junit.Assert.*;

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


/**
 * Tests the OIDC provider metadata class.
 *
 * @author Vladimir Dzhuvinov
 */
public class OIDCProviderMetadataTest {

	@Test
	public void testParseExample() throws Exception {

		String s = "{\n"
			+ "   \"version\": \"3.0\",\n"
			+ "   \"issuer\":\n"
			+ "     \"https://server.example.com\",\n"
			+ "   \"authorization_endpoint\":\n"
			+ "     \"https://server.example.com/connect/authorize\",\n"
			+ "   \"token_endpoint\":\n"
			+ "     \"https://server.example.com/connect/token\",\n"
			+ "   \"token_endpoint_auth_methods_supported\":\n"
			+ "     [\"client_secret_basic\", \"private_key_jwt\"],\n"
			+ "   \"token_endpoint_auth_signing_alg_values_supported\":\n"
			+ "     [\"RS256\", \"ES256\"],\n"
			+ "   \"userinfo_endpoint\":\n"
			+ "     \"https://server.example.com/connect/userinfo\",\n"
			+ "   \"check_session_iframe\":\n"
			+ "     \"https://server.example.com/connect/check_session\",\n"
			+ "   \"end_session_endpoint\":\n"
			+ "     \"https://server.example.com/connect/end_session\",\n"
			+ "   \"jwks_uri\":\n"
			+ "     \"https://server.example.com/jwks.json\",\n"
			+ "   \"registration_endpoint\":\n"
			+ "     \"https://server.example.com/connect/register\",\n"
			+ "   \"scopes_supported\":\n"
			+ "     [\"openid\", \"profile\", \"email\", \"address\",\n"
			+ "      \"phone\", \"offline_access\"],\n"
			+ "   \"response_types_supported\":\n"
			+ "     [\"code\", \"code id_token\", \"id_token\", \"token id_token\"],\n"
			+ "   \"acr_values_supported\":\n"
			+ "     [\"urn:mace:incommon:iap:silver\",\n"
			+ "      \"urn:mace:incommon:iap:bronze\"],\n"
			+ "   \"subject_types_supported\":\n"
			+ "     [\"public\", \"pairwise\"],\n"
			+ "   \"userinfo_signing_alg_values_supported\":\n"
			+ "     [\"RS256\", \"ES256\", \"HS256\"],\n"
			+ "   \"userinfo_encryption_alg_values_supported\":\n"
			+ "     [\"RSA1_5\", \"A128KW\"],\n"
			+ "   \"userinfo_encryption_enc_values_supported\":\n"
			+ "     [\"A128CBC-HS256\", \"A128GCM\"],\n"
			+ "   \"id_token_signing_alg_values_supported\":\n"
			+ "     [\"RS256\", \"ES256\", \"HS256\"],\n"
			+ "   \"id_token_encryption_alg_values_supported\":\n"
			+ "     [\"RSA1_5\", \"A128KW\"],\n"
			+ "   \"id_token_encryption_enc_values_supported\":\n"
			+ "     [\"A128CBC-HS256\", \"A128GCM\"],\n"
			+ "   \"request_object_signing_alg_values_supported\":\n"
			+ "     [\"none\", \"RS256\", \"ES256\"],\n"
			+ "   \"display_values_supported\":\n"
			+ "     [\"page\", \"popup\"],\n"
			+ "   \"claim_types_supported\":\n"
			+ "     [\"normal\", \"distributed\"],\n"
			+ "   \"claims_supported\":\n"
			+ "     [\"sub\", \"iss\", \"auth_time\", \"acr\",\n"
			+ "      \"name\", \"given_name\", \"family_name\", \"nickname\",\n"
			+ "      \"profile\", \"picture\", \"website\",\n"
			+ "      \"email\", \"email_verified\", \"locale\", \"zoneinfo\",\n"
			+ "      \"http://example.info/claims/groups\"],\n"
			+ "   \"claims_parameter_supported\":\n"
			+ "     true,\n"
			+ "   \"service_documentation\":\n"
			+ "     \"http://server.example.com/connect/service_documentation.html\",\n"
			+ "   \"ui_locales_supported\":\n"
			+ "     [\"en-US\", \"en-GB\", \"en-CA\", \"fr-FR\", \"fr-CA\"]\n"
			+ "  }";
		
		OIDCProviderMetadata op = OIDCProviderMetadata.parse(s);
		
		assertEquals("https://server.example.com", op.getIssuer().getValue());
		assertEquals("https://server.example.com/connect/authorize", op.getAuthorizationEndpointURL().toString());
		assertEquals("https://server.example.com/connect/token", op.getTokenEndpointURL().toString());
		
		Set<ClientAuthenticationMethod> authMethods = op.getTokenEndpointAuthMethods();
		assertTrue(authMethods.contains(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
		assertTrue(authMethods.contains(ClientAuthenticationMethod.PRIVATE_KEY_JWT));
		assertEquals(2, authMethods.size());
		
		Set<JWSAlgorithm> tokenEndpointJWSAlgs = op.getTokenEndpointJWSAlgs();
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
		
		Set<ResponseType> rts = op.getResponseTypes();
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
		
		Set<ACR> acrValues = op.getACRs();
		assertTrue(acrValues.contains(new ACR("urn:mace:incommon:iap:silver")));
		assertTrue(acrValues.contains(new ACR("urn:mace:incommon:iap:bronze")));
		assertEquals(2, acrValues.size());
		
		Set<SubjectType> subjectTypes = op.getSubjectTypes();
		assertTrue(subjectTypes.contains(SubjectType.PUBLIC));
		assertTrue(subjectTypes.contains(SubjectType.PAIRWISE));
		assertEquals(2, subjectTypes.size());
		
		// UserInfo
		Set<JWSAlgorithm> userInfoJWSAlgs = op.getUserInfoJWSAlgs();
		assertTrue(userInfoJWSAlgs.contains(JWSAlgorithm.RS256));
		assertTrue(userInfoJWSAlgs.contains(JWSAlgorithm.ES256));
		assertTrue(userInfoJWSAlgs.contains(JWSAlgorithm.HS256));
		assertEquals(3, userInfoJWSAlgs.size());
		
		Set<JWEAlgorithm> userInfoJWEalgs = op.getUserInfoJWEAlgs();
		assertTrue(userInfoJWEalgs.contains(JWEAlgorithm.RSA1_5));
		assertTrue(userInfoJWEalgs.contains(JWEAlgorithm.A128KW));
		assertEquals(2, userInfoJWEalgs.size());
		
		Set<EncryptionMethod> userInfoEncs = op.getUserInfoJWEEncs();
		assertTrue(userInfoEncs.contains(EncryptionMethod.A128CBC_HS256));
		assertTrue(userInfoEncs.contains(EncryptionMethod.A128GCM));
		assertEquals(2, userInfoEncs.size());
	
		// ID token
		Set<JWSAlgorithm> idTokenJWSAlgs = op.getIDTokenJWSAlgs();
		assertTrue(idTokenJWSAlgs.contains(JWSAlgorithm.RS256));
		assertTrue(idTokenJWSAlgs.contains(JWSAlgorithm.ES256));
		assertTrue(idTokenJWSAlgs.contains(JWSAlgorithm.HS256));
		assertEquals(3, idTokenJWSAlgs.size());
		
		Set<JWEAlgorithm> idTokenJWEAlgs = op.getIDTokenJWEAlgs();
		assertTrue(idTokenJWEAlgs.contains(JWEAlgorithm.RSA1_5));
		assertTrue(idTokenJWEAlgs.contains(JWEAlgorithm.A128KW));
		assertEquals(2, idTokenJWEAlgs.size());
		
		Set<EncryptionMethod> idTokenEncs = op.getIDTokenJWEEncs();
		assertTrue(idTokenEncs.contains(EncryptionMethod.A128CBC_HS256));
		assertTrue(idTokenEncs.contains(EncryptionMethod.A128GCM));
		assertEquals(2, idTokenEncs.size());
		
		// Request object
		Set<JWSAlgorithm> requestObjectJWSAlgs = op.getRequestObjectJWSAlgs();
		assertTrue(requestObjectJWSAlgs.contains(JWSAlgorithm.NONE));
		assertTrue(requestObjectJWSAlgs.contains(JWSAlgorithm.RS256));
		assertTrue(requestObjectJWSAlgs.contains(JWSAlgorithm.ES256));
		
		Set<Display> displayTypes = op.getDisplays();
		assertTrue(displayTypes.contains(Display.PAGE));
		assertTrue(displayTypes.contains(Display.POPUP));
		assertEquals(2, displayTypes.size());
		
		Set<ClaimType> claimTypes = op.getClaimTypes();
		assertTrue(claimTypes.contains(ClaimType.NORMAL));
		assertTrue(claimTypes.contains(ClaimType.DISTRIBUTED));
		assertEquals(2, claimTypes.size());
		
		Set<String> claims = op.getClaims();
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
		
		Set<LangTag> uiLocales = op.getUILocales();
		assertTrue(uiLocales.contains(LangTag.parse("en-US")));
		assertTrue(uiLocales.contains(LangTag.parse("en-GB")));
		assertTrue(uiLocales.contains(LangTag.parse("en-CA")));
		assertTrue(uiLocales.contains(LangTag.parse("fr-FR")));
		assertTrue(uiLocales.contains(LangTag.parse("fr-CA")));
		assertEquals(5, uiLocales.size());
	}
}
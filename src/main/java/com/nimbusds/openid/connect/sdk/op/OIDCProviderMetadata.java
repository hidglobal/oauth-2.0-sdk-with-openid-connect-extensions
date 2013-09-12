package com.nimbusds.openid.connect.sdk.op;


import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;

import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;

import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;

import com.nimbusds.openid.connect.sdk.Display;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.ClaimType;


/**
 * OpenID Connect provider metadata. This class is immutable.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Discovery 1.0, section 3.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
public class OIDCProviderMetadata {


	/**
	 * The version, set to "3.0".
	 */
	public final static String VERSION = "3.0";


	/**
	 * The issuer.
	 */
	private final Issuer issuer;


	/**
	 * The authorisation endpoint.
	 */
	private URL authzEndpoint;


	/**
	 * The token endpoint.
	 */
	private URL tokenEndpoint;


	/**
	 * The UserInfo endpoint.
	 */
	private URL userInfoEndpoint;


	/**
	 * The registration endpoint.
	 */
	private URL regEndpoint;
	
	
	/**
	 * The cross-origin check session iframe.
	 */
	private URL checkSessionIframe;
	
	
	/**
	 * The logout endpoint.
	 */
	private URL endSessionEndpoint;


	/**
	 * The JWK set URL.
	 */
	private URL jwkSetURI;


	/**
	 * The supported scope values.
	 */
	private Scope scope;


	/**
	 * The supported response types.
	 */
	private List<ResponseType> rts;
	
	
	/**
	 * The supported grant types.
	 */
	private List<GrantType> gts;


	/**
	 * The supported ACRs.
	 */
	private List<ACR> acrValues;


	/**
	 * The supported subject types.
	 */
	private final List<SubjectType> subjectTypes;


	/**
	 * The supported token endpoint authentication methods.
	 */
	private List<ClientAuthenticationMethod> tokenEndpointAuthMethods;


	/**
	 * The supported JWS algorithms for the {@code private_key_jwt} and 
	 * {@code client_secret_jwt} token endpoint authentication methods.
	 */
	private List<JWSAlgorithm> tokenEndpointJWSAlgs;


	/**
	 * The supported JWS algorithms for OpenID Connect request objects.
	 */
	private List<JWSAlgorithm> requestObjectJWSAlgs;


	/**
	 * The supported JWE algorithms for OpenID Connect request objects.
	 */
	private List<JWEAlgorithm> requestObjectJWEAlgs;


	/**
	 * The supported encryption methods for OpenID Connect request objects.
	 */
	private List<EncryptionMethod> requestObjectJWEEncs;


	/**
	 * The supported ID token JWS algorithms.
	 */
	private List<JWSAlgorithm> idTokenJWSAlgs;


	/**
	 * The supported ID token JWE algorithms.
	 */
	private List<JWEAlgorithm> idTokenJWEAlgs;


	/**
	 * The supported ID token encryption methods.
	 */
	private List<EncryptionMethod> idTokenJWEEncs;


	/**
	 * The supported UserInfo JWS algorithms.
	 */
	private List<JWSAlgorithm> userInfoJWSAlgs;


	/**
	 * The supported UserInfo JWE algorithms.
	 */
	private List<JWEAlgorithm> userInfoJWEAlgs;


	/**
	 * The supported UserInfo encryption methods.
	 */
	private List<EncryptionMethod> userInfoJWEEncs;


	/**
	 * The supported displays.
	 */
	private List<Display> displays;
	
	
	/**
	 * The supported claim types.
	 */
	private List<ClaimType> claimTypes;


	/**
	 * The supported claims names.
	 */
	private List<String> claims;
	
	
	/**
	 * The supported claims locales.
	 */
	private List<LangTag> claimsLocales;
	
	
	/**
	 * The supported UI locales.
	 */
	private List<LangTag> uiLocales;


	/**
	 * The service documentation URL.
	 */
	private URL serviceDocsURL;
	
	
	/**
	 * The provider's policy regarding relying party use of data.
	 */
	private URL policyURI;
	
	
	/**
	 * The provider's terms of service.
	 */
	private URL tosURI;
	
	
	/**
	 * If {@code true} the {@code claims} parameter is supported, else not.
	 */
	private boolean claimsParamSupported;
	
	
	/**
	 * If {@code true} the {@code request} parameter is supported, else 
	 * not.
	 */
	private boolean requestParamSupported;
	
	
	/**
	 * If {@code true} the {@code request_uri} parameter is supported, else
	 * not.
	 */
	private boolean requestURIParamSupported;
	
	
	/**
	 * If {@code true} the {@code request_uri} parameters must be
	 * pre-registered with the provider, else not.
	 */
	private boolean requireRequestURIReg;


	/**
	 * Creates a new OpenID Connect provider metadata instance.
	 * 
	 * @param issuer       The issuer identifier. Must be an URL using the 
	 *                     https scheme with no query or fragment 
	 *                     component. Must not be {@code null}.
	 * @param subjectTypes The supported subject types. At least one must
	 *                     be specified. Must not be {@code null}.
	 */
	protected OIDCProviderMetadata(final Issuer issuer, final List<SubjectType> subjectTypes) {
	
		URL url = null;
		
		try {
			url = new URL(issuer.getValue());
			
		} catch (MalformedURLException e) {
			
			throw new IllegalArgumentException("The issuer identifer must be a URL: " + e.getMessage(), e);
		}
		
		if (url.getQuery() != null)
			throw new IllegalArgumentException("The issuer URL must be without a query component");
		
		if (url.getRef() != null) 
			throw new IllegalArgumentException("The issuer URL must be without a fragment component ");
		
		this.issuer = issuer;
		
		
		if (subjectTypes.size() < 1)
			throw new IllegalArgumentException("At least one supported subject type must be specified");
		
		this.subjectTypes = subjectTypes;
	}


	/**
	 * Gets the issuer identifier. Corresponds to the {@code issuer} 
	 * metadata field.
	 *
	 * @return The issuer identifier.
	 */
	public Issuer getIssuer() {

		return issuer;
	}


	/**
	 * Gets the authorisation endpoint URL. Corresponds the 
	 * {@code authorization_endpoint} metadata field.
	 *
	 * @return The authorisation endpoint URL, {@code null} if not 
	 *         specified.
	 */
	public URL getAuthorizationEndpointURL() {

		return authzEndpoint;
	}


	/**
	 * Gets the token endpoint URL. Corresponds the {@code token_endpoint}
	 * metadata field.
	 *
	 * @return The token endpoint URL, {@code null} if not specified.
	 */
	public URL getTokenEndpointURL() {

		return tokenEndpoint;
	}


	/**
	 * Gets the UserInfo endpoint URL. Corresponds the 
	 * {@code userinfo_endpoint} metadata field.
	 *
	 * @return The UserInfo endpoint URL, {@code null} if not specified.
	 */
	public URL getUserInfoEndpointURL() {

		return userInfoEndpoint;
	}


	/**
	 * Gets the client registration endpoint URL. Corresponds to the
	 * {@code registration_endpoint} metadata field.
	 *
	 * @return The client registration endpoint URL, {@code null} if not
	 *         specified.
	 */
	public URL getRegistrationEndpointURL() {

		return regEndpoint;
	}
	
	
	/**
	 * Gets the cross-origin check session iframe URL. Corresponds to the
	 * {@code check_session_iframe} metadata field.
	 * 
	 * @return The check session iframe URL, {@code null} if not specified.
	 */
	public URL getCheckSessionIframeURL() {
		
		return checkSessionIframe;
	}
	
	
	/**
	 * Gets the logout endpoint URL. Corresponds to the 
	 * {@code end_session_endpoint} metadata field.
	 * 
	 * @return The logoout endpoint URL, {@code null} if not specified.
	 */
	public URL getEndSessionEndpointURL() {
		
		return endSessionEndpoint;
	}


	/**
	 * Gets the JSON Web Key (JWK) set URI. Corresponds to the
	 * {@code jwks_uri} metadata field.
	 *
	 * @return The JWK set URI, {@code null} if not specified.
	 */
	public URL getJWKSetURI() {

		return jwkSetURI;
	}


	/**
	 * Gets the supported scope values. Corresponds to the
	 * {@code scopes_supported} metadata field.
	 *
	 * @return The supported scope values, {@code null} if not specified.
	 */
	public Scope getScopes() {

		return scope;
	}


	/**
	 * Gets the supported response type values. Corresponds to the
	 * {@code response_types_supported} metadata field.
	 *
	 * @return The supported response type values, {@code null} if not 
	 *         specified.
	 */
	public List<ResponseType> getResponseTypes() {

		return rts;
	}
	
	
	/**
	 * Gets the supported OAuth 2.0 grant types. Corresponds to the
	 * {@code grant_types_supported} metadata field.
	 * 
	 * @return The supported grant types, {@code null} if not specified.
	 */
	public List<GrantType> getGrantTypes() {
		
		return gts;
	}


	/**
	 * Gets the supported Authentication Context Class References (ACRs).
	 * Corresponds to the {@code acr_values_supported} metadata field.
	 *
	 * @return The supported ACRs, {@code null} if not specified.
	 */
	public List<ACR> getACRs() {

		return acrValues;
	}


	/**
	 * Gets the supported subject types. Corresponds to the
	 * {@code subject_types_supported} metadata field.
	 *
	 * @return The supported subject types.
	 */
	public List<SubjectType> getSubjectTypes() {

		return subjectTypes;
	}


	/**
	 * Gets the supported token endpoint authentication methods. 
	 * Corresponds to the {@code token_endpoint_auth_methods_supported} 
	 * metadata field.
	 *
	 * @return The supported token endpoint authentication methods, 
	 *         {@code null} if not specified.
	 */
	public List<ClientAuthenticationMethod> getTokenEndpointAuthMethods() {

		return tokenEndpointAuthMethods;
	}


	/**
	 * Gets the supported JWS algorithms for the {@code private_key_jwt}
	 * and {@code client_secret_jwt} token endpoint authentication methods.
	 * Corresponds to the 
	 * {@code token_endpoint_auth_signing_alg_values_supported} metadata 
	 * field.
	 *
	 * @return The supported JWS algorithms, {@code null} if not specified.
	 */
	public List<JWSAlgorithm> getTokenEndpointJWSAlgs() {

		return tokenEndpointJWSAlgs;
	}


	/**
	 * Gets the supported JWS algorithms for OpenID Connect request 
	 * objects. Corresponds to the 
	 * {@code request_object_signing_alg_values_supported} metadata field.
	 *
	 * @return The supported JWS algorithms, {@code null} if not specified.
	 */
	public List<JWSAlgorithm> getRequestObjectJWSAlgs() {

		return requestObjectJWSAlgs;
	}


	/**
	 * Gets the supported JWE algorithms for OpenID Connect request 
	 * objects. Corresponds to the
	 * {@code request_object_encryption_alg_values_supported} metadata 
	 * field.
	 *
	 * @return The supported JWE algorithms, {@code null} if not specified.
	 */
	public List<JWEAlgorithm> getRequestObjectJWEAlgs() {

		return requestObjectJWEAlgs;
	}


	/**
	 * Gets the supported encryption methods for OpenID Connect request 
	 * objects. Corresponds to the 
	 * {@code request_object_encryption_enc_values_supported} metadata 
	 * field.
	 *
	 * @return The supported encryption methods, {@code null} if not 
	 *         specified.
	 */
	public List<EncryptionMethod> getRequestObjectJWEEncs() {

		return requestObjectJWEEncs;
	}


	/**
	 * Gets the supported JWS algorithms for ID tokens. Corresponds to the 
	 * {@code id_token_signing_alg_values_supported} metadata field.
	 *
	 * @return The supported JWS algorithms, {@code null} if not specified.
	 */
	public List<JWSAlgorithm> getIDTokenJWSAlgs() {

		return idTokenJWSAlgs;
	}


	/**
	 * Gets the supported JWE algorithms for ID tokens. Corresponds to the 
	 * {@code id_token_encryption_alg_values_supported} metadata field.
	 *
	 * @return The supported JWE algorithms, {@code null} if not specified.
	 */
	public List<JWEAlgorithm> getIDTokenJWEAlgs() {

		return idTokenJWEAlgs;
	}


	/**
	 * Gets the supported encryption methods for ID tokens. Corresponds to 
	 * the {@code id_token_encryption_enc_values_supported} metadata field.
	 *
	 * @return The supported encryption methods, {@code null} if not 
	 *         specified.
	 */
	public List<EncryptionMethod> getIDTokenJWEEncs() {

		return idTokenJWEEncs;
	}


	/**
	 * Gets the supported JWS algorithms for UserInfo JWTs. Corresponds to 
	 * the {@code userinfo_signing_alg_values_supported} metadata field.
	 *
	 * @return The supported JWS algorithms, {@code null} if not specified.
	 */
	public List<JWSAlgorithm> getUserInfoJWSAlgs() {

		return idTokenJWSAlgs;
	}


	/**
	 * Gets the supported JWE algorithms for UserInfo JWTs. Corresponds to 
	 * the {@code userinfo_encryption_alg_values_supported} metadata field.
	 *
	 * @return The supported JWE algorithms, {@code null} if not specified.
	 */
	public List<JWEAlgorithm> getUserInfoJWEAlgs() {

		return idTokenJWEAlgs;
	}


	/**
	 * Gets the supported encryption methods for UserInfo JWTs. Corresponds 
	 * to the {@code userinfo_encryption_enc_values_supported} metadata 
	 * field.
	 *
	 * @return The supported encryption methods, {@code null} if not 
	 *         specified.
	 */
	public List<EncryptionMethod> getUserInfoJWEEncs() {

		return idTokenJWEEncs;
	}


	/**
	 * Gets the supported displays. Corresponds to the 
	 * {@code display_values_supported} metadata field.
	 *
	 * @return The supported displays, {@code null} if not specified.
	 */
	public List<Display> getDisplays() {

		return displays;
	}
	
	
	/**
	 * Gets the supported claim types. Corresponds to the 
	 * {@code claim_types_supported} metadata field.
	 * 
	 * @return The supported claim types, {@code null} if not specified.
	 */
	public List<ClaimType> getClaimTypes() {
		
		return claimTypes;
	}


	/**
	 * Gets the supported claims names. Corresponds to the 
	 * {@code claims_supported} metadata field.
	 *
	 * @return The supported claims names, {@code null} if not specified.
	 */
	public List<String> getClaims() {

		return claims;
	}
	
	
	/**
	 * Gets the supported claims locales. Corresponds to the
	 * {@code claims_locales_supported} metadata field.
	 * 
	 * @return The supported claims locales, {@code null} if not specified.
	 */
	public List<LangTag> getClaimsLocales() {
		
		return claimsLocales;
	}
	
	
	/**
	 * Gets the supported UI locales. Corresponds to the 
	 * {@code ui_locales_supported} metadata field.
	 * 
	 * @return The supported UI locales, {@code null} if not specified.
	 */
	public List<LangTag> getUILocales() {
		
		return uiLocales;
	}


	/**
	 * Gets the service documentation URL. Corresponds to the 
	 * {@code service_documentation} metadata field.
	 *
	 * @return The service documentation URL, {@code null} if not 
	 *         specified.
	 */
	public URL getServiceDocsURL() {

		return serviceDocsURL;
	}
	
	
	/**
	 * Gets the provider's policy regarding relying party use of data.
	 * Corresponds to the {@code op_policy_uri} metadata field.
	 * 
	 * @return The policy URI, {@code null} if not specified.
	 */
	public URL getPolicyURI() {
		
		return policyURI;
	}
	
	
	/**
	 * Gets the provider's terms of service. Corresponds to the 
	 * {@code op_tos_uri} metadata field.
	 * 
	 * @return The terms of service URI, {@code null} if not specified.
	 */
	public URL getTermsOfServiceURI() {
		
		return tosURI;
	}
	
	
	/**
	 * Gets the support for the {@code claim} authorisation request
	 * parameter. Corresponds to the {@code claims_parameter_supported} 
	 * metadata field.
	 * 
	 * @return {@code true} if the {@code claim} parameter is supported,
	 *         else {@code false}.
	 */
	public boolean supportsClaimsParam() {
		
		return claimsParamSupported;
	}
	
	
	/**
	 * Gets the support for the {@code request} authorisation request
	 * parameter. Corresponds to the {@code request_parameter_supported}
	 * metadata field.
	 * 
	 * @return {@code true} if the {@code reqeust} parameter is supported,
	 *         else {@code false}.
	 */
	public boolean supportsRequestParam() {
		
		return requestParamSupported;
	}
	
	
	/**
	 * Gets the support for the {@code request_uri} authorisation request
	 * parameter. Corresponds the {@code request_uri_parameter_supported}
	 * metadata field.
	 * 
	 * @return {@code true} if the {@code request_uri} parameter is
	 *         supported, else {@code false}.
	 */
	public boolean supportsRequestURIParam() {
		
		return requestURIParamSupported;
	}
	
	
	/**
	 * Gets the requirement for the {@code request_uri} parameter 
	 * pre-registration. Corresponds to the 
	 * {@code require_request_uri_registration} metadata field.
	 * 
	 * @return {@code true} if the {@code request_uri} parameter values
	 *         must be pre-registered, else {@code false}.
	 */
	public boolean requiresRequestURIRegistration() {
		
		return requireRequestURIReg;
	}


	/**
	 * Parses an OpenID Connect provider metadata from the specified JSON 
	 * object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The OpenID Connect provider metadata.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an
	 *                        OpenID Connect provider metadata.
	 */
	public static OIDCProviderMetadata parse(final JSONObject jsonObject)
		throws ParseException {

		String version = JSONObjectUtils.getString(jsonObject, "version");

		if(! version.equals(VERSION))
			throw new ParseException("The version must be \"3.0\"");

		// Parse issuer and subject_types_supported first
		
		List<SubjectType> subjectTypes = new ArrayList<SubjectType>();
		
		for (String v: JSONObjectUtils.getStringArray(jsonObject, "subject_types_supported")) {
			subjectTypes.add(SubjectType.parse(v));
		}
		
		Issuer issuer = new Issuer(JSONObjectUtils.getURL(jsonObject, "issuer").toString());
		
		
		OIDCProviderMetadata op = new OIDCProviderMetadata(issuer, Collections.unmodifiableList(subjectTypes));

		// Endpoints
		if (jsonObject.containsKey("authorization_endpoint"))
			op.authzEndpoint = JSONObjectUtils.getURL(jsonObject, "authorization_endpoint");

		if (jsonObject.containsKey("token_endpoint"))
			op.tokenEndpoint = JSONObjectUtils.getURL(jsonObject, "token_endpoint");

		if (jsonObject.containsKey("userinfo_endpoint"))
			op.userInfoEndpoint = JSONObjectUtils.getURL(jsonObject, "userinfo_endpoint");
		
		if (jsonObject.containsKey("registration_endpoint"))
			op.regEndpoint = JSONObjectUtils.getURL(jsonObject, "registration_endpoint");
		
		if (jsonObject.containsKey("check_session_iframe"))
			op.checkSessionIframe = JSONObjectUtils.getURL(jsonObject, "check_session_iframe");
		
		if (jsonObject.containsKey("end_session_endpoint"))
			op.endSessionEndpoint = JSONObjectUtils.getURL(jsonObject, "end_session_endpoint");
		

		// JWK set
		if (jsonObject.containsKey("jwks_uri"))
			op.jwkSetURI = JSONObjectUtils.getURL(jsonObject, "jwks_uri");

		// OIDC capabilities
		if (jsonObject.containsKey("scopes_supported")) {

			op.scope = new Scope();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "scopes_supported")) {

				if (v != null)
					op.scope.add(new Scope.Value(v));
			}
		}

		if (jsonObject.containsKey("response_types_supported")) {

			op.rts = new ArrayList<ResponseType>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "response_types_supported")) {

				if (v != null)
					op.rts.add(ResponseType.parse(v));
			}
		}
		
		if (jsonObject.containsKey("grant_types_supported")) {
			
			op.gts = new ArrayList<GrantType>();
			
			for (String v: JSONObjectUtils.getStringArray(jsonObject, "grant_types_supported")) {
				
				if (v != null)
					op.gts.add(new GrantType(v));
			}
		}

		if (jsonObject.containsKey("acr_values_supported")) {

			op.acrValues = new ArrayList<ACR>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "acr_values_supported")) {

				if (v != null)
					op.acrValues.add(new ACR(v));
			}
		}

		if (jsonObject.containsKey("token_endpoint_auth_methods_supported")) {
			
			op.tokenEndpointAuthMethods = new ArrayList<ClientAuthenticationMethod>();
			
			for (String v: JSONObjectUtils.getStringArray(jsonObject, "token_endpoint_auth_methods_supported")) {
				
				if (v != null)
					op.tokenEndpointAuthMethods.add(new ClientAuthenticationMethod(v));
			}
		}
		
		if (jsonObject.containsKey("token_endpoint_auth_signing_alg_values_supported")) {
			
			op.tokenEndpointJWSAlgs = new ArrayList<JWSAlgorithm>();
			
			for (String v: JSONObjectUtils.getStringArray(jsonObject, "token_endpoint_auth_signing_alg_values_supported")) {
				
				if (v != null)
					op.tokenEndpointJWSAlgs.add(new JWSAlgorithm(v));
			}
		}
		
		
		// OpenID Connect request object

		if (jsonObject.containsKey("request_object_signing_alg_values_supported")) {

			op.requestObjectJWSAlgs = new ArrayList<JWSAlgorithm>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "request_object_signing_alg_values_supported")) {

				if (v != null)
					op.requestObjectJWSAlgs.add(new JWSAlgorithm(v));
			}
		}


		if (jsonObject.containsKey("request_object_encryption_alg_values_supported")) {

			op.requestObjectJWEAlgs = new ArrayList<JWEAlgorithm>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "request_object_encryption_alg_values_supported")) {

				if (v != null)
					op.requestObjectJWEAlgs.add(new JWEAlgorithm(v));
			}
		}


		if (jsonObject.containsKey("request_object_encryption_enc_values_supported")) {

			op.requestObjectJWEEncs = new ArrayList<EncryptionMethod>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "request_object_encryption_enc_values_supported")) {

				if (v != null)
					op.requestObjectJWEEncs.add(new EncryptionMethod(v));
			}
		}
		
		
		// ID token

		if (jsonObject.containsKey("id_token_signing_alg_values_supported")) {

			op.idTokenJWSAlgs = new ArrayList<JWSAlgorithm>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "id_token_signing_alg_values_supported")) {

				if (v != null)
					op.idTokenJWSAlgs.add(new JWSAlgorithm(v));
			}
		}


		if (jsonObject.containsKey("id_token_encryption_alg_values_supported")) {

			op.idTokenJWEAlgs = new ArrayList<JWEAlgorithm>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "id_token_encryption_alg_values_supported")) {

				if (v != null)
					op.idTokenJWEAlgs.add(new JWEAlgorithm(v));
			}
		}


		if (jsonObject.containsKey("id_token_encryption_enc_values_supported")) {

			op.idTokenJWEEncs = new ArrayList<EncryptionMethod>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "id_token_encryption_enc_values_supported")) {

				if (v != null)
					op.idTokenJWEEncs.add(new EncryptionMethod(v));
			}
		}

		// UserInfo

		if (jsonObject.containsKey("userinfo_signing_alg_values_supported")) {

			op.userInfoJWSAlgs = new ArrayList<JWSAlgorithm>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "userinfo_signing_alg_values_supported")) {

				if (v != null)
					op.userInfoJWSAlgs.add(new JWSAlgorithm(v));
			}
		}


		if (jsonObject.containsKey("userinfo_encryption_alg_values_supported")) {

			op.userInfoJWEAlgs = new ArrayList<JWEAlgorithm>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "userinfo_encryption_alg_values_supported")) {

				if (v != null)
					op.userInfoJWEAlgs.add(new JWEAlgorithm(v));
			}
		}


		if (jsonObject.containsKey("userinfo_encryption_enc_values_supported")) {

			op.userInfoJWEEncs = new ArrayList<EncryptionMethod>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "userinfo_encryption_enc_values_supported")) {

					if (v != null)
						op.userInfoJWEEncs.add(new EncryptionMethod(v));
			}
		}

		
		// Misc

		if (jsonObject.containsKey("display_values_supported")) {

			op.displays = new ArrayList<Display>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "display_values_supported")) {

				if (v != null)
					op.displays.add(Display.parse(v));
			}
		}
		
		if (jsonObject.containsKey("claim_types_supported")) {
			
			op.claimTypes = new ArrayList<ClaimType>();
			
			for (String v: JSONObjectUtils.getStringArray(jsonObject, "claim_types_supported")) {
				
				if (v != null)
					op.claimTypes.add(ClaimType.parse(v));
			}
		}


		if (jsonObject.containsKey("claims_supported")) {

			op.claims = new ArrayList<String>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "claims_supported")) {

				if (v != null)
					op.claims.add(v);
			}
		}
		
		if (jsonObject.containsKey("claims_locales_supported")) {
			
			op.claimsLocales = new ArrayList<LangTag>();
			
			for (String v : JSONObjectUtils.getStringArray(jsonObject, "claims_locales_supported")) {
				
				if (v != null) {
					
					try {
						op.claimsLocales.add(LangTag.parse(v));
					
					} catch (LangTagException e) {
						
						throw new ParseException("Invalid claims_locales_supported field: " + e.getMessage(), e);
					}
				}
			}
		}
		
		if (jsonObject.containsKey("ui_locales_supported")) {
			
			op.uiLocales = new ArrayList<LangTag>();
			
			for (String v : JSONObjectUtils.getStringArray(jsonObject, "ui_locales_supported")) {
				
				if (v != null) {
					
					try {
						op.uiLocales.add(LangTag.parse(v));
					
					} catch (LangTagException e) {
						
						throw new ParseException("Invalid ui_locales_supported field: " + e.getMessage(), e);
					}
				}
			}
		}


		if (jsonObject.containsKey("service_documentation"))
			op.serviceDocsURL = JSONObjectUtils.getURL(jsonObject, "service_documentation");
		
		if (jsonObject.containsKey("op_policy_uri"))
			op.policyURI = JSONObjectUtils.getURL(jsonObject, "op_policy_uri");
		
		if (jsonObject.containsKey("op_tos_uri"))
			op.tosURI = JSONObjectUtils.getURL(jsonObject, "op_tos_uri");
		
		if (jsonObject.containsKey("claims_parameter_supported"))
			op.claimsParamSupported = JSONObjectUtils.getBoolean(jsonObject, "claims_parameter_supported");
		
		if (jsonObject.containsKey("request_parameter_supported"))
			op.requestParamSupported = JSONObjectUtils.getBoolean(jsonObject, "request_parameter_supported");
		
		if (jsonObject.containsKey("request_uri_parameter_supported"))
			op.requestURIParamSupported = JSONObjectUtils.getBoolean(jsonObject, "request_uri_parameter_supported");
		
		if (jsonObject.containsKey("require_request_uri_registration"))
			op.requireRequestURIReg = JSONObjectUtils.getBoolean(jsonObject, "require_request_uri_registration");

		return op;
	}


	/**
	 * Parses an OpenID Connect provider metadata from the specified JSON 
	 * object string.
	 *
	 * @param s The JSON object sting to parse. Must not be {@code null}.
	 *
	 * @return The OpenID Connect provider metadata.
	 *
	 * @throws ParseException If the JSON object string couldn't be parsed
	 *                        to an OpenID Connect provider metadata.
	 */
	public static OIDCProviderMetadata parse(final String s)
		throws ParseException {

		return parse(JSONObjectUtils.parseJSONObject(s));
	}
}
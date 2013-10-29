package com.nimbusds.openid.connect.sdk.op;


import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

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
	 * The registered parameter names.
	 */
	private static final Set<String> REGISTERED_PARAMETER_NAMES;


	/**
	 * Initialises the registered parameter name set.
	 */
	static {
		Set<String> p = new HashSet<String>();

		p.add("issuer");
		p.add("authorization_endpoint");
		p.add("token_endpoint");
		p.add("userinfo_endpoint");
		p.add("registration_endpoint");
		p.add("check_session_iframe");
		p.add("end_session_endpoint");
		p.add("jwks_uri");
		p.add("scopes_supported");
		p.add("response_types_supported");
		p.add("response_modes_supported");
		p.add("grant_types_supported");
		p.add("acr_values_supported");
		p.add("subject_types_supported");
		p.add("token_endpoint_auth_methods_supported");
		p.add("token_endpoint_auth_signing_alg_values_supported");
		p.add("request_object_signing_alg_values_supported");
		p.add("request_object_encryption_alg_values_supported");
		p.add("request_object_encryption_enc_values_supported");
		p.add("id_token_signing_alg_values_supported");
		p.add("id_token_encryption_alg_values_supported");
		p.add("id_token_encryption_enc_values_supported");
		p.add("userinfo_signing_alg_values_supported");
		p.add("userinfo_encryption_alg_values_supported");
		p.add("userinfo_encryption_enc_values_supported");
		p.add("display_values_supported");
		p.add("claim_types_supported");
		p.add("claims_supported");
		p.add("claims_locales_supported");
		p.add("ui_locales_supported");
		p.add("service_documentation");
		p.add("op_policy_uri");
		p.add("op_tos_uri");
		p.add("claims_parameter_supported");
		p.add("request_parameter_supported");
		p.add("request_uri_parameter_supported");
		p.add("require_request_uri_registration");

		REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
	}


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
	private final URL jwkSetURI;


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
	private boolean claimsParamSupported = false;
	
	
	/**
	 * If {@code true} the {@code request} parameter is supported, else 
	 * not.
	 */
	private boolean requestParamSupported = false;
	
	
	/**
	 * If {@code true} the {@code request_uri} parameter is supported, else
	 * not.
	 */
	private boolean requestURIParamSupported = true;
	
	
	/**
	 * If {@code true} the {@code request_uri} parameters must be
	 * pre-registered with the provider, else not.
	 */
	private boolean requireRequestURIReg = false;


	/**
	 * Creates a new OpenID Connect provider metadata instance.
	 * 
	 * @param issuer       The issuer identifier. Must be an URL using the 
	 *                     https scheme with no query or fragment 
	 *                     component. Must not be {@code null}.
	 * @param subjectTypes The supported subject types. At least one must
	 *                     be specified. Must not be {@code null}.
	 */
	public OIDCProviderMetadata(final Issuer issuer,
				    final List<SubjectType> subjectTypes,
				    final URL jwkSetURI) {
	
		URL url;
		
		try {
			url = new URL(issuer.getValue());
			
		} catch (MalformedURLException e) {
			
			throw new IllegalArgumentException("The issuer identifier must be a URL: " + e.getMessage(), e);
		}
		
		if (url.getQuery() != null)
			throw new IllegalArgumentException("The issuer URL must be without a query component");
		
		if (url.getRef() != null) 
			throw new IllegalArgumentException("The issuer URL must be without a fragment component ");
		
		this.issuer = issuer;
		
		
		if (subjectTypes.size() < 1)
			throw new IllegalArgumentException("At least one supported subject type must be specified");
		
		this.subjectTypes = subjectTypes;

		if (jwkSetURI == null)
			throw new IllegalArgumentException("The public JWK set URI must not be null");

		this.jwkSetURI = jwkSetURI;
	}


	/**
	 * Gets the registered OpenID Connect provider metadata parameter
	 * names.
	 *
	 * @return The registered OpenID Connect provider metadata parameter
	 *         names, as an unmodifiable set.
	 */
	public static Set<String> getRegisteredParameterNames() {

		return REGISTERED_PARAMETER_NAMES;
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
	 * Sets the authorisation endpoint URL. Corresponds the
	 * {@code authorization_endpoint} metadata field.
	 *
	 * @param authzEndpoint The authorisation endpoint URL, {@code null} if
	 *                      not specified.
	 */
	public void setAuthorizationEndpointURL(final URL authzEndpoint) {

		this.authzEndpoint = authzEndpoint;
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
	 * Sts the token endpoint URL. Corresponds the {@code token_endpoint}
	 * metadata field.
	 *
	 * @param tokenEndpoint The token endpoint URL, {@code null} if not
	 *                      specified.
	 */
	public void setTokenEndpointURL(final URL tokenEndpoint) {

		this.tokenEndpoint = tokenEndpoint;
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
	 * Sets the UserInfo endpoint URL. Corresponds the
	 * {@code userinfo_endpoint} metadata field.
	 *
	 * @param userInfoEndpoint The UserInfo endpoint URL, {@code null} if
	 *                         not specified.
	 */
	public void setUserInfoEndpointURL(final URL userInfoEndpoint) {

		this.userInfoEndpoint = userInfoEndpoint;
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
	 * Sets the client registration endpoint URL. Corresponds to the
	 * {@code registration_endpoint} metadata field.
	 *
	 * @param regEndpoint The client registration endpoint URL,
	 *                    {@code null} if not specified.
	 */
	public void setRegistrationEndpointURL(final URL regEndpoint) {

		this.regEndpoint = regEndpoint;
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
	 * Sets the cross-origin check session iframe URL. Corresponds to the
	 * {@code check_session_iframe} metadata field.
	 *
	 * @param checkSessionIframe The check session iframe URL, {@code null}
	 *                           if not specified.
	 */
	public void setCheckSessionIframeURL(final URL checkSessionIframe) {

		this.checkSessionIframe = checkSessionIframe;
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
	 * Sets the logout endpoint URL. Corresponds to the
	 * {@code end_session_endpoint} metadata field.
	 *
	 * @param endSessionEndpoint The logoout endpoint URL, {@code null} if
	 *                           not specified.
	 */
	public void setEndSessionEndpointURL(final URL endSessionEndpoint) {

		this.endSessionEndpoint = endSessionEndpoint;
	}


	/**
	 * Gets the JSON Web Key (JWK) set URI. Corresponds to the
	 * {@code jwks_uri} metadata field.
	 *
	 * @return The JWK set URI.
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
	 * Sets the supported scope values. Corresponds to the
	 * {@code scopes_supported} metadata field.
	 *
	 * @param scope The supported scope values, {@code null} if not
	 *              specified.
	 */
	public void setScopes(final Scope scope) {

		this.scope = scope;
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
	 * Sets the supported response type values. Corresponds to the
	 * {@code response_types_supported} metadata field.
	 *
	 * @param rts The supported response type values, {@code null} if not
	 *            specified.
	 */
	public void setResponseTypes(final List<ResponseType> rts) {

		this.rts = rts;
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
	 * Sets the supported OAuth 2.0 grant types. Corresponds to the
	 * {@code grant_types_supported} metadata field.
	 *
	 * @param gts The supported grant types, {@code null} if not specified.
	 */
	public void setGrantTypes(final List<GrantType> gts) {

		this.gts = gts;
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
	 * Sets the supported Authentication Context Class References (ACRs).
	 * Corresponds to the {@code acr_values_supported} metadata field.
	 *
	 * @param acrValues The supported ACRs, {@code null} if not specified.
	 */
	public void setACRs(final List<ACR> acrValues) {

		this.acrValues = acrValues;
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
	 * Sets the supported token endpoint authentication methods.
	 * Corresponds to the {@code token_endpoint_auth_methods_supported}
	 * metadata field.
	 *
	 * @param tokenEndpointAuthMethods The supported token endpoint
	 *                                 authentication methods, {@code null}
	 *                                 if not specified.
	 */
	public void setTokenEndpointAuthMethods(final List<ClientAuthenticationMethod> tokenEndpointAuthMethods) {

		this.tokenEndpointAuthMethods = tokenEndpointAuthMethods;
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
	 * Sets the supported JWS algorithms for the {@code private_key_jwt}
	 * and {@code client_secret_jwt} token endpoint authentication methods.
	 * Corresponds to the
	 * {@code token_endpoint_auth_signing_alg_values_supported} metadata
	 * field.
	 *
	 * @param tokenEndpointJWSAlgs The supported JWS algorithms,
	 *                             {@code null} if not specified.
	 */
	public void setTokenEndpointJWSAlgs(final List<JWSAlgorithm> tokenEndpointJWSAlgs) {

		this.tokenEndpointJWSAlgs = tokenEndpointJWSAlgs;
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
	 * Sets the supported JWS algorithms for OpenID Connect request
	 * objects. Corresponds to the
	 * {@code request_object_signing_alg_values_supported} metadata field.
	 *
	 * @param requestObjectJWSAlgs The supported JWS algorithms,
	 *                             {@code null} if not specified.
	 */
	public void setRequestObjectJWSAlgs(final List<JWSAlgorithm> requestObjectJWSAlgs) {

		this.requestObjectJWSAlgs = requestObjectJWSAlgs;
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
	 * Sets the supported JWE algorithms for OpenID Connect request
	 * objects. Corresponds to the
	 * {@code request_object_encryption_alg_values_supported} metadata
	 * field.
	 *
	 * @param requestObjectJWEAlgs The supported JWE algorithms,
	 *                            {@code null} if not specified.
	 */
	public void setRequestObjectJWEAlgs(final List<JWEAlgorithm> requestObjectJWEAlgs) {

		this.requestObjectJWEAlgs = requestObjectJWEAlgs;
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
	 * Sets the supported encryption methods for OpenID Connect request
	 * objects. Corresponds to the
	 * {@code request_object_encryption_enc_values_supported} metadata
	 * field.
	 *
	 * @param requestObjectJWEEncs The supported encryption methods,
	 *                             {@code null} if not specified.
	 */
	public void setRequestObjectJWEEncs(final List<EncryptionMethod> requestObjectJWEEncs) {

		this.requestObjectJWEEncs = requestObjectJWEEncs;
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
	 * Sets the supported JWS algorithms for ID tokens. Corresponds to the
	 * {@code id_token_signing_alg_values_supported} metadata field.
	 *
	 * @param idTokenJWSAlgs The supported JWS algorithms, {@code null} if
	 *                       not specified.
	 */
	public void setIdTokenJWSAlgs(final List<JWSAlgorithm> idTokenJWSAlgs) {

		this.idTokenJWSAlgs = idTokenJWSAlgs;
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
	 * Sets the supported JWE algorithms for ID tokens. Corresponds to the
	 * {@code id_token_encryption_alg_values_supported} metadata field.
	 *
	 * @param idTokenJWEAlgs The supported JWE algorithms, {@code null} if
	 *                       not specified.
	 */
	public void setIDTokenJWEAlgs(final List<JWEAlgorithm> idTokenJWEAlgs) {

		this.idTokenJWEAlgs = idTokenJWEAlgs;
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
	 * Sets the supported encryption methods for ID tokens. Corresponds to
	 * the {@code id_token_encryption_enc_values_supported} metadata field.
	 *
	 * @param idTokenJWEEncs The supported encryption methods, {@code null}
	 *                       if not specified.
	 */
	public void setIdTokenJWEEncs(final List<EncryptionMethod> idTokenJWEEncs) {

		this.idTokenJWEEncs = idTokenJWEEncs;
	}


	/**
	 * Gets the supported JWS algorithms for UserInfo JWTs. Corresponds to 
	 * the {@code userinfo_signing_alg_values_supported} metadata field.
	 *
	 * @return The supported JWS algorithms, {@code null} if not specified.
	 */
	public List<JWSAlgorithm> getUserInfoJWSAlgs() {

		return userInfoJWSAlgs;
	}


	/**
	 * Sets the supported JWS algorithms for UserInfo JWTs. Corresponds to
	 * the {@code userinfo_signing_alg_values_supported} metadata field.
	 *
	 * @param userInfoJWSAlgs The supported JWS algorithms, {@code null} if
	 *                        not specified.
	 */
	public void setUserInfoJWSAlgs(final List<JWSAlgorithm> userInfoJWSAlgs) {

		this.userInfoJWSAlgs = userInfoJWSAlgs;
	}


	/**
	 * Gets the supported JWE algorithms for UserInfo JWTs. Corresponds to 
	 * the {@code userinfo_encryption_alg_values_supported} metadata field.
	 *
	 * @return The supported JWE algorithms, {@code null} if not specified.
	 */
	public List<JWEAlgorithm> getUserInfoJWEAlgs() {

		return userInfoJWEAlgs;
	}


	/**
	 * Sets the supported JWE algorithms for UserInfo JWTs. Corresponds to
	 * the {@code userinfo_encryption_alg_values_supported} metadata field.
	 *
	 * @param userInfoJWEAlgs The supported JWE algorithms, {@code null} if
	 *                        not specified.
	 */
	public void setUserInfoJWEAlgs(final List<JWEAlgorithm> userInfoJWEAlgs) {

		this.userInfoJWEAlgs = userInfoJWEAlgs;
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

		return userInfoJWEEncs;
	}


	/**
	 * Sets the supported encryption methods for UserInfo JWTs. Corresponds
	 * to the {@code userinfo_encryption_enc_values_supported} metadata
	 * field.
	 *
	 * @param userInfoJWEEncs The supported encryption methods,
	 *                        {@code null} if not specified.
	 */
	public void setUserInfoJWEEncs(final List<EncryptionMethod> userInfoJWEEncs) {

		this.userInfoJWEEncs = userInfoJWEEncs;
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
	 * Sets the supported displays. Corresponds to the
	 * {@code display_values_supported} metadata field.
	 *
	 * @param displays The supported displays, {@code null} if not
	 *                 specified.
	 */
	public void setDisplays(final List<Display> displays) {

		this.displays = displays;
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
	 * Sets the supported claim types. Corresponds to the
	 * {@code claim_types_supported} metadata field.
	 *
	 * @param claimTypes The supported claim types, {@code null} if not
	 *                   specified.
	 */
	public void setClaimTypes(final List<ClaimType> claimTypes) {

		this.claimTypes = claimTypes;
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
	 * Sets the supported claims names. Corresponds to the
	 * {@code claims_supported} metadata field.
	 *
	 * @param claims The supported claims names, {@code null} if not
	 *               specified.
	 */
	public void setClaims(final List<String> claims) {

		this.claims = claims;
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
	 * Sets the supported claims locales. Corresponds to the
	 * {@code claims_locales_supported} metadata field.
	 *
	 * @param claimsLocales The supported claims locales, {@code null} if
	 *                      not specified.
	 */
	public void setClaimLocales(final List<LangTag> claimsLocales) {

		this.claimsLocales = claimsLocales;
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
	 * Sets the supported UI locales. Corresponds to the
	 * {@code ui_locales_supported} metadata field.
	 *
	 * @param uiLocales The supported UI locales, {@code null} if not
	 *                  specified.
	 */
	public void setUILocales(final List<LangTag> uiLocales) {

		this.uiLocales = uiLocales;
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
	 * Sets the service documentation URL. Corresponds to the
	 * {@code service_documentation} metadata field.
	 *
	 * @param serviceDocsURL The service documentation URL, {@code null} if
	 *                       not specified.
	 */
	public void setServiceDocsURL(final URL serviceDocsURL) {

		this.serviceDocsURL = serviceDocsURL;
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
	 * Sets the provider's policy regarding relying party use of data.
	 * Corresponds to the {@code op_policy_uri} metadata field.
	 *
	 * @param policyURI The policy URI, {@code null} if not specified.
	 */
	public void setPolicyURI(final URL policyURI) {

		this.policyURI = policyURI;
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
	 * Sets the provider's terms of service. Corresponds to the
	 * {@code op_tos_uri} metadata field.
	 *
	 * @param tosURI The terms of service URI, {@code null} if not
	 *               specified.
	 */
	public void setTermsOfServiceURI(final URL tosURI) {

		this.tosURI = tosURI;
	}
	
	
	/**
	 * Gets the support for the {@code claims} authorisation request
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
	 * Sets the support for the {@code claims} authorisation request
	 * parameter. Corresponds to the {@code claims_parameter_supported}
	 * metadata field.
	 *
	 * @param claimsParamSupported {@code true} if the {@code claim}
	 *                             parameter is supported, else
	 *                             {@code false}.
	 */
	public void setSupportsClaimsParams(final boolean claimsParamSupported) {

		this.claimsParamSupported = claimsParamSupported;
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
	 * Sets the support for the {@code request} authorisation request
	 * parameter. Corresponds to the {@code request_parameter_supported}
	 * metadata field.
	 *
	 * @param requestParamSupported {@code true} if the {@code reqeust}
	 *                              parameter is supported, else
	 *                              {@code false}.
	 */
	public void setSupportsRequestParam(final boolean requestParamSupported) {

		this.requestParamSupported = requestParamSupported;
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
	 * Sets the support for the {@code request_uri} authorisation request
	 * parameter. Corresponds the {@code request_uri_parameter_supported}
	 * metadata field.
	 *
	 * @param requestURIParamSupported {@code true} if the
	 *                                 {@code request_uri} parameter is
	 *                                 supported, else {@code false}.
	 */
	public void setSupportsRequestURIParam(final boolean requestURIParamSupported) {

		this.requestURIParamSupported = requestURIParamSupported;
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
	 * Sets the requirement for the {@code request_uri} parameter
	 * pre-registration. Corresponds to the
	 * {@code require_request_uri_registration} metadata field.
	 *
	 * @param requireRequestURIReg {@code true} if the {@code request_uri}
	 *                             parameter values must be pre-registered,
	 *                             else {@code false}.
	 */
	public void setRequiresRequestURIRegistration(final boolean requireRequestURIReg) {

		this.requireRequestURIReg = requireRequestURIReg;
	}


	/**
	 * Returns the JSON object representation of this OpenID Connect
	 * provider metadata.
	 *
	 * @return The JSON object representation.
	 */
	public JSONObject toJSONObject() {

		JSONObject o = new JSONObject();

		// Mandatory fields

		o.put("issuer", issuer.getValue());

		List<String> stringList = new ArrayList<String>(subjectTypes.size());

		for (SubjectType st: subjectTypes)
			stringList.add(st.toString());

		o.put("subject_types_supported", stringList);

		o.put("jwks_uri", jwkSetURI.toString());

		// Optional fields

		if (authzEndpoint != null)
			o.put("authorization_endpoint", authzEndpoint.toString());

		if (tokenEndpoint != null)
			o.put("token_endpoint", tokenEndpoint.toString());

		if (userInfoEndpoint != null)
			o.put("userinfo_endpoint", userInfoEndpoint.toString());

		if (regEndpoint != null)
			o.put("registration_endpoint", regEndpoint.toString());

		if (checkSessionIframe != null)
			o.put("check_session_iframe", checkSessionIframe.toString());

		if (endSessionEndpoint != null)
			o.put("end_session_endpoint", endSessionEndpoint.toString());

		if (scope != null)
			o.put("scopes_supported", scope.toStringList());

		if (rts != null) {

			stringList = new ArrayList<String>(rts.size());

			for (ResponseType rt: rts)
				stringList.add(rt.toString());

			o.put("response_types_supported", stringList);
		}

		if (gts != null) {

			stringList = new ArrayList<String>(gts.size());

			for (GrantType gt: gts)
				stringList.add(gt.toString());

			o.put("grant_types_supported", stringList);
		}

		if (acrValues != null) {

			stringList = new ArrayList<String>(acrValues.size());

			for (ACR acr: acrValues)
				stringList.add(acr.getValue());

			o.put("acr_values_supported", stringList);
		}


		if (tokenEndpointAuthMethods != null) {

			stringList = new ArrayList<String>(tokenEndpointAuthMethods.size());

			for (ClientAuthenticationMethod m: tokenEndpointAuthMethods)
				stringList.add(m.getValue());

			o.put("token_endpoint_auth_methods_supported", stringList);
		}

		if (tokenEndpointJWSAlgs != null) {

			stringList = new ArrayList<String>(tokenEndpointJWSAlgs.size());

			for (JWSAlgorithm alg: tokenEndpointJWSAlgs)
				stringList.add(alg.getName());

			o.put("token_endpoint_auth_signing_alg_values_supported", stringList);
		}

		if (requestObjectJWSAlgs != null) {

			stringList = new ArrayList<String>(requestObjectJWSAlgs.size());

			for (JWSAlgorithm alg: requestObjectJWSAlgs)
				stringList.add(alg.getName());

			o.put("request_object_signing_alg_values_supported", stringList);
		}

		if (requestObjectJWEAlgs != null) {

			stringList = new ArrayList<String>(requestObjectJWEAlgs.size());

			for (JWEAlgorithm alg: requestObjectJWEAlgs)
				stringList.add(alg.getName());

			o.put("request_object_encryption_alg_values_supported", stringList);
		}

		if (requestObjectJWEEncs != null) {

			stringList = new ArrayList<String>(requestObjectJWEEncs.size());

			for (EncryptionMethod m: requestObjectJWEEncs)
				stringList.add(m.getName());

			o.put("request_object_encryption_enc_values_supported", stringList);
		}

		if (idTokenJWSAlgs != null) {

			stringList = new ArrayList<String>(idTokenJWEAlgs.size());

			for (JWSAlgorithm alg: idTokenJWSAlgs)
				stringList.add(alg.getName());

			o.put("id_token_signing_alg_values_supported", stringList);
		}

		if (idTokenJWEAlgs != null) {

			stringList = new ArrayList<String>(idTokenJWEAlgs.size());

			for (JWEAlgorithm alg: idTokenJWEAlgs)
				stringList.add(alg.getName());

			o.put("id_token_encryption_alg_values_supported", stringList);
		}

		if (idTokenJWEEncs != null) {

			stringList = new ArrayList<String>(idTokenJWEEncs.size());

			for (EncryptionMethod m: idTokenJWEEncs)
				stringList.add(m.getName());

			o.put("id_token_encryption_enc_values_supported", stringList);
		}

		if (userInfoJWSAlgs != null) {

			stringList = new ArrayList<String>(userInfoJWSAlgs.size());

			for (JWSAlgorithm alg: userInfoJWSAlgs)
				stringList.add(alg.getName());

			o.put("userinfo_signing_alg_values_supported", stringList);
		}

		if (userInfoJWEAlgs != null) {

			stringList = new ArrayList<String>(userInfoJWEAlgs.size());

			for (JWEAlgorithm alg: userInfoJWEAlgs)
				stringList.add(alg.getName());

			o.put("userinfo_encryption_alg_values_supported", stringList);
		}

		if (userInfoJWEEncs != null) {

			stringList = new ArrayList<String>(userInfoJWEEncs.size());

			for (EncryptionMethod m: userInfoJWEEncs)
				stringList.add(m.getName());

			o.put("userinfo_encryption_enc_values_supported", stringList);
		}

		if (displays != null) {

			stringList = new ArrayList<String>(displays.size());

			for (Display d: displays)
				stringList.add(d.toString());

			o.put("display_values_supported", stringList);
		}

		if (claimTypes != null) {

			stringList = new ArrayList<String>(claimTypes.size());

			for (ClaimType ct: claimTypes)
				stringList.add(ct.toString());

			o.put("claim_types_supported", stringList);
		}

		if (claims != null)
			o.put("claims_supported", claims);

		if (claimsLocales != null) {

			stringList = new ArrayList<String>(claimsLocales.size());

			for (LangTag l: claimsLocales)
				stringList.add(l.toString());

			o.put("claims_locales_supported", stringList);
		}

		if (uiLocales != null) {

			stringList = new ArrayList<String>(uiLocales.size());

			for (LangTag l: uiLocales)
				stringList.add(l.toString());

			o.put("ui_locales_supported", stringList);
		}

		if (serviceDocsURL != null)
			o.put("service_documentation", serviceDocsURL.toString());

		if (policyURI != null)
			o.put("op_policy_uri", policyURI.toString());

		if (tosURI != null)
			o.put("op_tos_uri", tosURI.toString());

		o.put("claims_parameter_supported", claimsParamSupported);

		o.put("request_parameter_supported", requestParamSupported);

		o.put("request_uri_parameter_supported", requestURIParamSupported);

		o.put("require_request_uri_registration", requireRequestURIReg);

		return o;
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

		// Parse issuer and subject_types_supported first
		
		List<SubjectType> subjectTypes = new ArrayList<SubjectType>();
		
		for (String v: JSONObjectUtils.getStringArray(jsonObject, "subject_types_supported")) {
			subjectTypes.add(SubjectType.parse(v));
		}
		
		Issuer issuer = new Issuer(JSONObjectUtils.getURL(jsonObject, "issuer").toString());

		URL jwkSetURI = JSONObjectUtils.getURL(jsonObject, "jwks_uri");
		
		
		OIDCProviderMetadata op = new OIDCProviderMetadata(issuer, Collections.unmodifiableList(subjectTypes), jwkSetURI);

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
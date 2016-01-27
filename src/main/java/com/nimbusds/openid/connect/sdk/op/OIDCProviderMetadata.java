package com.nimbusds.openid.connect.sdk.op;


import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.Display;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.ClaimType;
import net.minidev.json.JSONObject;


/**
 * OpenID Connect provider metadata.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Discovery 1.0, section 3.
 * </ul>
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
		Set<String> p = new HashSet<>();

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
		p.add("code_challenge_methods_supported");
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
	private URI authzEndpoint;


	/**
	 * The token endpoint.
	 */
	private URI tokenEndpoint;


	/**
	 * The UserInfo endpoint.
	 */
	private URI userInfoEndpoint;


	/**
	 * The registration endpoint.
	 */
	private URI regEndpoint;
	
	
	/**
	 * The cross-origin check session iframe.
	 */
	private URI checkSessionIframe;
	
	
	/**
	 * The logout endpoint.
	 */
	private URI endSessionEndpoint;


	/**
	 * The JWK set URI.
	 */
	private final URI jwkSetURI;


	/**
	 * The supported scope values.
	 */
	private Scope scope;


	/**
	 * The supported response types.
	 */
	private List<ResponseType> rts;


	/**
	 * The supported response modes.
	 */
	private List<ResponseMode> rms;
	
	
	/**
	 * The supported grant types.
	 */
	private List<GrantType> gts;


	/**
	 * The supported code challenge methods for PKCE.
	 */
	private List<CodeChallengeMethod> codeChallengeMethods;


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
	 * The service documentation URI.
	 */
	private URI serviceDocsURI;
	
	
	/**
	 * The provider's policy regarding relying party use of data.
	 */
	private URI policyURI;
	
	
	/**
	 * The provider's terms of service.
	 */
	private URI tosURI;
	
	
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
	 * Custom (not-registered) parameters.
	 */
	private final JSONObject customParameters = new JSONObject();


	/**
	 * Creates a new OpenID Connect provider metadata instance.
	 * 
	 * @param issuer       The issuer identifier. Must be an URI using the
	 *                     https scheme with no query or fragment 
	 *                     component. Must not be {@code null}.
	 * @param subjectTypes The supported subject types. At least one must
	 *                     be specified. Must not be {@code null}.
	 */
	public OIDCProviderMetadata(final Issuer issuer,
				    final List<SubjectType> subjectTypes,
				    final URI jwkSetURI) {
	
		URI url;
		
		try {
			url = new URI(issuer.getValue());
			
		} catch (URISyntaxException e) {
			
			throw new IllegalArgumentException("The issuer identifier must be a URI: " + e.getMessage(), e);
		}
		
		if (url.getRawQuery() != null)
			throw new IllegalArgumentException("The issuer URI must be without a query component");
		
		if (url.getRawFragment() != null)
			throw new IllegalArgumentException("The issuer URI must be without a fragment component ");
		
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
	 * Gets the authorisation endpoint URI. Corresponds the
	 * {@code authorization_endpoint} metadata field.
	 *
	 * @return The authorisation endpoint URI, {@code null} if not
	 *         specified.
	 */
	public URI getAuthorizationEndpointURI() {

		return authzEndpoint;
	}


	/**
	 * Sets the authorisation endpoint URI. Corresponds the
	 * {@code authorization_endpoint} metadata field.
	 *
	 * @param authzEndpoint The authorisation endpoint URI, {@code null} if
	 *                      not specified.
	 */
	public void setAuthorizationEndpointURI(final URI authzEndpoint) {

		this.authzEndpoint = authzEndpoint;
	}


	/**
	 * Gets the token endpoint URI. Corresponds the {@code token_endpoint}
	 * metadata field.
	 *
	 * @return The token endpoint URI, {@code null} if not specified.
	 */
	public URI getTokenEndpointURI() {

		return tokenEndpoint;
	}


	/**
	 * Sts the token endpoint URI. Corresponds the {@code token_endpoint}
	 * metadata field.
	 *
	 * @param tokenEndpoint The token endpoint URI, {@code null} if not
	 *                      specified.
	 */
	public void setTokenEndpointURI(final URI tokenEndpoint) {

		this.tokenEndpoint = tokenEndpoint;
	}


	/**
	 * Gets the UserInfo endpoint URI. Corresponds the
	 * {@code userinfo_endpoint} metadata field.
	 *
	 * @return The UserInfo endpoint URI, {@code null} if not specified.
	 */
	public URI getUserInfoEndpointURI() {

		return userInfoEndpoint;
	}


	/**
	 * Sets the UserInfo endpoint URI. Corresponds the
	 * {@code userinfo_endpoint} metadata field.
	 *
	 * @param userInfoEndpoint The UserInfo endpoint URI, {@code null} if
	 *                         not specified.
	 */
	public void setUserInfoEndpointURI(final URI userInfoEndpoint) {

		this.userInfoEndpoint = userInfoEndpoint;
	}


	/**
	 * Gets the client registration endpoint URI. Corresponds to the
	 * {@code registration_endpoint} metadata field.
	 *
	 * @return The client registration endpoint URI, {@code null} if not
	 *         specified.
	 */
	public URI getRegistrationEndpointURI() {

		return regEndpoint;
	}


	/**
	 * Sets the client registration endpoint URI. Corresponds to the
	 * {@code registration_endpoint} metadata field.
	 *
	 * @param regEndpoint The client registration endpoint URI,
	 *                    {@code null} if not specified.
	 */
	public void setRegistrationEndpointURI(final URI regEndpoint) {

		this.regEndpoint = regEndpoint;
	}
	
	
	/**
	 * Gets the cross-origin check session iframe URI. Corresponds to the
	 * {@code check_session_iframe} metadata field.
	 * 
	 * @return The check session iframe URI, {@code null} if not specified.
	 */
	public URI getCheckSessionIframeURI() {
		
		return checkSessionIframe;
	}


	/**
	 * Sets the cross-origin check session iframe URI. Corresponds to the
	 * {@code check_session_iframe} metadata field.
	 *
	 * @param checkSessionIframe The check session iframe URI, {@code null}
	 *                           if not specified.
	 */
	public void setCheckSessionIframeURI(final URI checkSessionIframe) {

		this.checkSessionIframe = checkSessionIframe;
	}
	
	
	/**
	 * Gets the logout endpoint URI. Corresponds to the
	 * {@code end_session_endpoint} metadata field.
	 * 
	 * @return The logoout endpoint URI, {@code null} if not specified.
	 */
	public URI getEndSessionEndpointURI() {
		
		return endSessionEndpoint;
	}


	/**
	 * Sets the logout endpoint URI. Corresponds to the
	 * {@code end_session_endpoint} metadata field.
	 *
	 * @param endSessionEndpoint The logoout endpoint URI, {@code null} if
	 *                           not specified.
	 */
	public void setEndSessionEndpointURI(final URI endSessionEndpoint) {

		this.endSessionEndpoint = endSessionEndpoint;
	}


	/**
	 * Gets the JSON Web Key (JWK) set URI. Corresponds to the
	 * {@code jwks_uri} metadata field.
	 *
	 * @return The JWK set URI.
	 */
	public URI getJWKSetURI() {

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
	 * Gets the supported response mode values. Corresponds to the
	 * {@code response_modes_supported}.
	 *
	 * @return The supported response mode values, {@code null} if not
	 *         specified.
	 */
	public List<ResponseMode> getResponseModes() {

		return rms;
	}


	/**
	 * Sets the supported response mode values. Corresponds to the
	 * {@code response_modes_supported}.
	 *
	 * @param rms The supported response mode values, {@code null} if not
	 *            specified.
	 */
	public void setResponseModes(final List<ResponseMode> rms) {

		this.rms = rms;
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
	 * Gets the supported authorisation code challenge methods for PKCE.
	 * Corresponds to the {@code code_challenge_methods_supported} metadata
	 * field.
	 *
	 * @return The supported code challenge methods, {@code null} if not
	 *         specified.
	 */
	public List<CodeChallengeMethod> getCodeChallengeMethods() {

		return codeChallengeMethods;
	}


	/**
	 * Gets the supported authorisation code challenge methods for PKCE.
	 * Corresponds to the {@code code_challenge_methods_supported} metadata
	 * field.
	 *
	 * @param codeChallengeMethods The supported code challenge methods,
	 *                             {@code null} if not specified.
	 */
	public void setCodeChallengeMethods(final List<CodeChallengeMethod> codeChallengeMethods) {

		this.codeChallengeMethods = codeChallengeMethods;
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
	 *                             {@code null} if not specified. Must not
	 *                             contain the {@code none} algorithm.
	 */
	public void setTokenEndpointJWSAlgs(final List<JWSAlgorithm> tokenEndpointJWSAlgs) {

		if (tokenEndpointJWSAlgs != null && tokenEndpointJWSAlgs.contains(Algorithm.NONE))
			throw new IllegalArgumentException("The none algorithm is not accepted");

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
	public void setIDTokenJWSAlgs(final List<JWSAlgorithm> idTokenJWSAlgs) {

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
	public void setIDTokenJWEEncs(final List<EncryptionMethod> idTokenJWEEncs) {

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
	 * Gets the service documentation URI. Corresponds to the
	 * {@code service_documentation} metadata field.
	 *
	 * @return The service documentation URI, {@code null} if not
	 *         specified.
	 */
	public URI getServiceDocsURI() {

		return serviceDocsURI;
	}


	/**
	 * Sets the service documentation URI. Corresponds to the
	 * {@code service_documentation} metadata field.
	 *
	 * @param serviceDocsURI The service documentation URI, {@code null} if
	 *                       not specified.
	 */
	public void setServiceDocsURI(final URI serviceDocsURI) {

		this.serviceDocsURI = serviceDocsURI;
	}
	
	
	/**
	 * Gets the provider's policy regarding relying party use of data.
	 * Corresponds to the {@code op_policy_uri} metadata field.
	 * 
	 * @return The policy URI, {@code null} if not specified.
	 */
	public URI getPolicyURI() {
		
		return policyURI;
	}


	/**
	 * Sets the provider's policy regarding relying party use of data.
	 * Corresponds to the {@code op_policy_uri} metadata field.
	 *
	 * @param policyURI The policy URI, {@code null} if not specified.
	 */
	public void setPolicyURI(final URI policyURI) {

		this.policyURI = policyURI;
	}
	
	
	/**
	 * Gets the provider's terms of service. Corresponds to the 
	 * {@code op_tos_uri} metadata field.
	 * 
	 * @return The terms of service URI, {@code null} if not specified.
	 */
	public URI getTermsOfServiceURI() {
		
		return tosURI;
	}


	/**
	 * Sets the provider's terms of service. Corresponds to the
	 * {@code op_tos_uri} metadata field.
	 *
	 * @param tosURI The terms of service URI, {@code null} if not
	 *               specified.
	 */
	public void setTermsOfServiceURI(final URI tosURI) {

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
	 * Gets the specified custom (not registered) parameter.
	 *
	 * @param name The parameter name. Must not be {@code null}.
	 *
	 * @return The parameter value, {@code null} if not specified.
	 */
	public Object getCustomParameter(final String name) {

		return customParameters.get(name);
	}


	/**
	 * Gets the specified custom (not registered) URI parameter.
	 *
	 * @param name The parameter name. Must not be {@code null}.
	 *
	 * @return The parameter URI value, {@code null} if not specified.
	 */
	public URI getCustomURIParameter(final String name) {

		try {
			return JSONObjectUtils.getURI(customParameters, name);
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Sets the specified custom (not registered) parameter.
	 *
	 * @param name  The parameter name. Must not be {@code null}.
	 * @param value The parameter value, {@code null} if not specified.
	 */
	public void setCustomParameter(final String name, final Object value) {

		if (REGISTERED_PARAMETER_NAMES.contains(name)) {
			throw new IllegalArgumentException("The " + name + " parameter is registered");
		}

		customParameters.put(name, value);
	}


	/**
	 * Gets the custom (not registered) parameters.
	 *
	 * @return The custom parameters, empty JSON object if none.
	 */
	public JSONObject getCustomParameters() {

		return customParameters;
	}


	/**
	 * Applies the OpenID Connect provider metadata defaults where no
	 * values have been specified.
	 *
	 * <ul>
	 *     <li>The response modes default to {@code ["query", "fragment"]}.
	 *     <li>The grant types default to {@code ["authorization_code",
	 *         "implicit"]}.
	 *     <li>The token endpoint authentication methods default to
	 *         {@code ["client_secret_basic"]}.
	 *     <li>The claim types default to {@code ["normal]}.
	 * </ul>
	 */
	public void applyDefaults() {

		if (rms == null) {
			rms = new ArrayList<>(2);
			rms.add(ResponseMode.QUERY);
			rms.add(ResponseMode.FRAGMENT);
		}

		if (gts == null) {
			gts = new ArrayList<>(2);
			gts.add(GrantType.AUTHORIZATION_CODE);
			gts.add(GrantType.IMPLICIT);
		}

		if (claimTypes == null) {
			claimTypes = new ArrayList<>(1);
			claimTypes.add(ClaimType.NORMAL);
		}
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

		List<String> stringList = new ArrayList<>(subjectTypes.size());

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

			stringList = new ArrayList<>(rts.size());

			for (ResponseType rt: rts)
				stringList.add(rt.toString());

			o.put("response_types_supported", stringList);
		}

		if (rms != null) {

			stringList = new ArrayList<>(rms.size());

			for (ResponseMode rm: rms)
				stringList.add(rm.getValue());

			o.put("response_modes_supported", stringList);
		}

		if (gts != null) {

			stringList = new ArrayList<>(gts.size());

			for (GrantType gt: gts)
				stringList.add(gt.toString());

			o.put("grant_types_supported", stringList);
		}

		if (codeChallengeMethods != null) {

			stringList = new ArrayList<>(codeChallengeMethods.size());

			for (CodeChallengeMethod m: codeChallengeMethods)
				stringList.add(m.getValue());

			o.put("code_challenge_methods_supported", stringList);
		}

		if (acrValues != null) {

			stringList = new ArrayList<>(acrValues.size());

			for (ACR acr: acrValues)
				stringList.add(acr.getValue());

			o.put("acr_values_supported", stringList);
		}


		if (tokenEndpointAuthMethods != null) {

			stringList = new ArrayList<>(tokenEndpointAuthMethods.size());

			for (ClientAuthenticationMethod m: tokenEndpointAuthMethods)
				stringList.add(m.getValue());

			o.put("token_endpoint_auth_methods_supported", stringList);
		}

		if (tokenEndpointJWSAlgs != null) {

			stringList = new ArrayList<>(tokenEndpointJWSAlgs.size());

			for (JWSAlgorithm alg: tokenEndpointJWSAlgs)
				stringList.add(alg.getName());

			o.put("token_endpoint_auth_signing_alg_values_supported", stringList);
		}

		if (requestObjectJWSAlgs != null) {

			stringList = new ArrayList<>(requestObjectJWSAlgs.size());

			for (JWSAlgorithm alg: requestObjectJWSAlgs)
				stringList.add(alg.getName());

			o.put("request_object_signing_alg_values_supported", stringList);
		}

		if (requestObjectJWEAlgs != null) {

			stringList = new ArrayList<>(requestObjectJWEAlgs.size());

			for (JWEAlgorithm alg: requestObjectJWEAlgs)
				stringList.add(alg.getName());

			o.put("request_object_encryption_alg_values_supported", stringList);
		}

		if (requestObjectJWEEncs != null) {

			stringList = new ArrayList<>(requestObjectJWEEncs.size());

			for (EncryptionMethod m: requestObjectJWEEncs)
				stringList.add(m.getName());

			o.put("request_object_encryption_enc_values_supported", stringList);
		}

		if (idTokenJWSAlgs != null) {

			stringList = new ArrayList<>(idTokenJWSAlgs.size());

			for (JWSAlgorithm alg: idTokenJWSAlgs)
				stringList.add(alg.getName());

			o.put("id_token_signing_alg_values_supported", stringList);
		}

		if (idTokenJWEAlgs != null) {

			stringList = new ArrayList<>(idTokenJWEAlgs.size());

			for (JWEAlgorithm alg: idTokenJWEAlgs)
				stringList.add(alg.getName());

			o.put("id_token_encryption_alg_values_supported", stringList);
		}

		if (idTokenJWEEncs != null) {

			stringList = new ArrayList<>(idTokenJWEEncs.size());

			for (EncryptionMethod m: idTokenJWEEncs)
				stringList.add(m.getName());

			o.put("id_token_encryption_enc_values_supported", stringList);
		}

		if (userInfoJWSAlgs != null) {

			stringList = new ArrayList<>(userInfoJWSAlgs.size());

			for (JWSAlgorithm alg: userInfoJWSAlgs)
				stringList.add(alg.getName());

			o.put("userinfo_signing_alg_values_supported", stringList);
		}

		if (userInfoJWEAlgs != null) {

			stringList = new ArrayList<>(userInfoJWEAlgs.size());

			for (JWEAlgorithm alg: userInfoJWEAlgs)
				stringList.add(alg.getName());

			o.put("userinfo_encryption_alg_values_supported", stringList);
		}

		if (userInfoJWEEncs != null) {

			stringList = new ArrayList<>(userInfoJWEEncs.size());

			for (EncryptionMethod m: userInfoJWEEncs)
				stringList.add(m.getName());

			o.put("userinfo_encryption_enc_values_supported", stringList);
		}

		if (displays != null) {

			stringList = new ArrayList<>(displays.size());

			for (Display d: displays)
				stringList.add(d.toString());

			o.put("display_values_supported", stringList);
		}

		if (claimTypes != null) {

			stringList = new ArrayList<>(claimTypes.size());

			for (ClaimType ct: claimTypes)
				stringList.add(ct.toString());

			o.put("claim_types_supported", stringList);
		}

		if (claims != null)
			o.put("claims_supported", claims);

		if (claimsLocales != null) {

			stringList = new ArrayList<>(claimsLocales.size());

			for (LangTag l: claimsLocales)
				stringList.add(l.toString());

			o.put("claims_locales_supported", stringList);
		}

		if (uiLocales != null) {

			stringList = new ArrayList<>(uiLocales.size());

			for (LangTag l: uiLocales)
				stringList.add(l.toString());

			o.put("ui_locales_supported", stringList);
		}

		if (serviceDocsURI != null)
			o.put("service_documentation", serviceDocsURI.toString());

		if (policyURI != null)
			o.put("op_policy_uri", policyURI.toString());

		if (tosURI != null)
			o.put("op_tos_uri", tosURI.toString());

		o.put("claims_parameter_supported", claimsParamSupported);

		o.put("request_parameter_supported", requestParamSupported);

		o.put("request_uri_parameter_supported", requestURIParamSupported);

		o.put("require_request_uri_registration", requireRequestURIReg);

		// Append any custom (not registered) parameters
		o.putAll(customParameters);

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
		
		List<SubjectType> subjectTypes = new ArrayList<>();
		
		for (String v: JSONObjectUtils.getStringArray(jsonObject, "subject_types_supported")) {
			subjectTypes.add(SubjectType.parse(v));
		}
		
		Issuer issuer = new Issuer(JSONObjectUtils.getURI(jsonObject, "issuer").toString());

		URI jwkSetURI = JSONObjectUtils.getURI(jsonObject, "jwks_uri");
		
		
		OIDCProviderMetadata op = new OIDCProviderMetadata(issuer, Collections.unmodifiableList(subjectTypes), jwkSetURI);

		// Endpoints
		if (jsonObject.containsKey("authorization_endpoint"))
			op.authzEndpoint = JSONObjectUtils.getURI(jsonObject, "authorization_endpoint");

		if (jsonObject.containsKey("token_endpoint"))
			op.tokenEndpoint = JSONObjectUtils.getURI(jsonObject, "token_endpoint");

		if (jsonObject.containsKey("userinfo_endpoint"))
			op.userInfoEndpoint = JSONObjectUtils.getURI(jsonObject, "userinfo_endpoint");
		
		if (jsonObject.containsKey("registration_endpoint"))
			op.regEndpoint = JSONObjectUtils.getURI(jsonObject, "registration_endpoint");
		
		if (jsonObject.containsKey("check_session_iframe"))
			op.checkSessionIframe = JSONObjectUtils.getURI(jsonObject, "check_session_iframe");
		
		if (jsonObject.containsKey("end_session_endpoint"))
			op.endSessionEndpoint = JSONObjectUtils.getURI(jsonObject, "end_session_endpoint");

		// OIDC capabilities
		if (jsonObject.containsKey("scopes_supported")) {

			op.scope = new Scope();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "scopes_supported")) {

				if (v != null)
					op.scope.add(new Scope.Value(v));
			}
		}

		if (jsonObject.containsKey("response_types_supported")) {

			op.rts = new ArrayList<>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "response_types_supported")) {

				if (v != null)
					op.rts.add(ResponseType.parse(v));
			}
		}

		if (jsonObject.containsKey("response_modes_supported")) {

			op.rms = new ArrayList<>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "response_modes_supported")) {

				if (v != null)
					op.rms.add(new ResponseMode(v));
			}
		}
		
		if (jsonObject.containsKey("grant_types_supported")) {
			
			op.gts = new ArrayList<>();
			
			for (String v: JSONObjectUtils.getStringArray(jsonObject, "grant_types_supported")) {
				
				if (v != null)
					op.gts.add(GrantType.parse(v));
			}
		}

		if (jsonObject.containsKey("code_challenge_methods_supported")) {

			op.codeChallengeMethods = new ArrayList<>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "code_challenge_methods_supported")) {

				if (v != null)
					op.codeChallengeMethods.add(CodeChallengeMethod.parse(v));
			}
		}

		if (jsonObject.containsKey("acr_values_supported")) {

			op.acrValues = new ArrayList<>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "acr_values_supported")) {

				if (v != null)
					op.acrValues.add(new ACR(v));
			}
		}

		if (jsonObject.containsKey("token_endpoint_auth_methods_supported")) {
			
			op.tokenEndpointAuthMethods = new ArrayList<>();
			
			for (String v: JSONObjectUtils.getStringArray(jsonObject, "token_endpoint_auth_methods_supported")) {
				
				if (v != null)
					op.tokenEndpointAuthMethods.add(new ClientAuthenticationMethod(v));
			}
		}
		
		if (jsonObject.containsKey("token_endpoint_auth_signing_alg_values_supported")) {
			
			op.tokenEndpointJWSAlgs = new ArrayList<>();
			
			for (String v: JSONObjectUtils.getStringArray(jsonObject, "token_endpoint_auth_signing_alg_values_supported")) {

				if (v != null && v.equals(Algorithm.NONE.getName()))
					throw new ParseException("The none algorithm is not accepted");
				
				if (v != null)
					op.tokenEndpointJWSAlgs.add(new JWSAlgorithm(v));
			}
		}
		
		
		// OpenID Connect request object

		if (jsonObject.containsKey("request_object_signing_alg_values_supported")) {

			op.requestObjectJWSAlgs = new ArrayList<>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "request_object_signing_alg_values_supported")) {

				if (v != null)
					op.requestObjectJWSAlgs.add(new JWSAlgorithm(v));
			}
		}


		if (jsonObject.containsKey("request_object_encryption_alg_values_supported")) {

			op.requestObjectJWEAlgs = new ArrayList<>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "request_object_encryption_alg_values_supported")) {

				if (v != null)
					op.requestObjectJWEAlgs.add(new JWEAlgorithm(v));
			}
		}


		if (jsonObject.containsKey("request_object_encryption_enc_values_supported")) {

			op.requestObjectJWEEncs = new ArrayList<>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "request_object_encryption_enc_values_supported")) {

				if (v != null)
					op.requestObjectJWEEncs.add(new EncryptionMethod(v));
			}
		}
		
		
		// ID token

		if (jsonObject.containsKey("id_token_signing_alg_values_supported")) {

			op.idTokenJWSAlgs = new ArrayList<>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "id_token_signing_alg_values_supported")) {

				if (v != null)
					op.idTokenJWSAlgs.add(new JWSAlgorithm(v));
			}
		}


		if (jsonObject.containsKey("id_token_encryption_alg_values_supported")) {

			op.idTokenJWEAlgs = new ArrayList<>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "id_token_encryption_alg_values_supported")) {

				if (v != null)
					op.idTokenJWEAlgs.add(new JWEAlgorithm(v));
			}
		}


		if (jsonObject.containsKey("id_token_encryption_enc_values_supported")) {

			op.idTokenJWEEncs = new ArrayList<>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "id_token_encryption_enc_values_supported")) {

				if (v != null)
					op.idTokenJWEEncs.add(new EncryptionMethod(v));
			}
		}

		// UserInfo

		if (jsonObject.containsKey("userinfo_signing_alg_values_supported")) {

			op.userInfoJWSAlgs = new ArrayList<>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "userinfo_signing_alg_values_supported")) {

				if (v != null)
					op.userInfoJWSAlgs.add(new JWSAlgorithm(v));
			}
		}


		if (jsonObject.containsKey("userinfo_encryption_alg_values_supported")) {

			op.userInfoJWEAlgs = new ArrayList<>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "userinfo_encryption_alg_values_supported")) {

				if (v != null)
					op.userInfoJWEAlgs.add(new JWEAlgorithm(v));
			}
		}


		if (jsonObject.containsKey("userinfo_encryption_enc_values_supported")) {

			op.userInfoJWEEncs = new ArrayList<>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "userinfo_encryption_enc_values_supported")) {

					if (v != null)
						op.userInfoJWEEncs.add(new EncryptionMethod(v));
			}
		}

		
		// Misc

		if (jsonObject.containsKey("display_values_supported")) {

			op.displays = new ArrayList<>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "display_values_supported")) {

				if (v != null)
					op.displays.add(Display.parse(v));
			}
		}
		
		if (jsonObject.containsKey("claim_types_supported")) {
			
			op.claimTypes = new ArrayList<>();
			
			for (String v: JSONObjectUtils.getStringArray(jsonObject, "claim_types_supported")) {
				
				if (v != null)
					op.claimTypes.add(ClaimType.parse(v));
			}
		}


		if (jsonObject.containsKey("claims_supported")) {

			op.claims = new ArrayList<>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "claims_supported")) {

				if (v != null)
					op.claims.add(v);
			}
		}
		
		if (jsonObject.containsKey("claims_locales_supported")) {
			
			op.claimsLocales = new ArrayList<>();
			
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
			
			op.uiLocales = new ArrayList<>();
			
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
			op.serviceDocsURI = JSONObjectUtils.getURI(jsonObject, "service_documentation");
		
		if (jsonObject.containsKey("op_policy_uri"))
			op.policyURI = JSONObjectUtils.getURI(jsonObject, "op_policy_uri");
		
		if (jsonObject.containsKey("op_tos_uri"))
			op.tosURI = JSONObjectUtils.getURI(jsonObject, "op_tos_uri");
		
		if (jsonObject.containsKey("claims_parameter_supported"))
			op.claimsParamSupported = JSONObjectUtils.getBoolean(jsonObject, "claims_parameter_supported");
		
		if (jsonObject.containsKey("request_parameter_supported"))
			op.requestParamSupported = JSONObjectUtils.getBoolean(jsonObject, "request_parameter_supported");
		
		if (jsonObject.containsKey("request_uri_parameter_supported"))
			op.requestURIParamSupported = JSONObjectUtils.getBoolean(jsonObject, "request_uri_parameter_supported");
		
		if (jsonObject.containsKey("require_request_uri_registration"))
			op.requireRequestURIReg = JSONObjectUtils.getBoolean(jsonObject, "require_request_uri_registration");

		// Parse custom (not registered) parameters
		JSONObject customParams = new JSONObject(jsonObject);
		customParams.keySet().removeAll(REGISTERED_PARAMETER_NAMES);
		for (Map.Entry<String,Object> customEntry: customParams.entrySet()) {
			op.setCustomParameter(customEntry.getKey(), customEntry.getValue());
		}

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

		return parse(JSONObjectUtils.parse(s));
	}
}
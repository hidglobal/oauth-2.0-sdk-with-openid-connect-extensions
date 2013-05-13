package com.nimbusds.openid.connect.sdk.op;


import java.net.URL;

import java.util.LinkedHashSet;
import java.util.Set;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.ScopeToken;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.ResponseTypeSet;

import com.nimbusds.oauth2.sdk.id.Issuer;

import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;

import com.nimbusds.openid.connect.sdk.Display;
import com.nimbusds.openid.connect.sdk.SubjectType;

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;

import com.nimbusds.openid.connect.sdk.claims.ACR;


/**
 * Public OpenID Connect provider configuration. This class is immutable.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Discovery 1.0, section 3.2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-02-13)
 */
public class ProviderConfiguration {


	/**
	 * The version, set to "3.0".
	 */
	public final static String VERSION = "3.0";


	/**
	 * The issuer.
	 */
	private Issuer issuer;


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
	 * The JWK set URL.
	 */
	private URL jwkSetURL;


	/**
	 * The encryption JWK set URL.
	 */
	private URL encryptionJWKSetURL;


	/**
	 * The X.509 URL.
	 */
	private URL x509URL;


	/**
	 * The encryption X.509 URL.
	 */
	private URL encryptionX509URL;


	/**
	 * The supported scope values.
	 */
	private Scope scope;


	/**
	 * The supported response types.
	 */
	private ResponseTypeSet rts;


	/**
	 * The supported ACRs.
	 */
	private Set<ACR> acrValues;


	/**
	 * The supported subject types.
	 */
	private Set<SubjectType> subjectTypes;


	/**
	 * The supported token endpoint authentication methods.
	 */
	private Set<ClientAuthenticationMethod> tokenEndpointAuthMethods;


	/**
	 * The supported JWS algorithms for the {@code private_key_jwt} and 
	 * {@code client_secret_jwt} token endpoint authentication methods.
	 */
	private Set<JWSAlgorithm> tokenEndpointJWSAlgs;


	/**
	 * The supported JWS algorithms for OpenID request objects.
	 */
	private Set<JWSAlgorithm> requestObjectJWSAlgs;


	/**
	 * The supported JWE algorithms for OpenID request objects.
	 */
	private Set<JWEAlgorithm> requestObjectJWEAlgs;


	/**
	 * The supported encryption methods for OpenID request objects.
	 */
	private Set<EncryptionMethod> requestObjectJWEEncs;


	/**
	 * The supported ID token JWS algorithms.
	 */
	private Set<JWSAlgorithm> idTokenJWSAlgs;


	/**
	 * The supported ID token JWE algorithms.
	 */
	private Set<JWEAlgorithm> idTokenJWEAlgs;


	/**
	 * The supported ID token encryption methods.
	 */
	private Set<EncryptionMethod> idTokenJWEEncs;


	/**
	 * The supported UserInfo JWS algorithms.
	 */
	private Set<JWSAlgorithm> userInfoJWSAlgs;


	/**
	 * The supported UserInfo JWE algorithms.
	 */
	private Set<JWEAlgorithm> userInfoJWEAlgs;


	/**
	 * The supported UserInfo encryption methods.
	 */
	private Set<EncryptionMethod> userInfoJWEEncs;


	/**
	 * The supported displays.
	 */
	private Set<Display> displays;


	/**
	 * The names of the supported claims.
	 */
	private Set<String> claims;


	/**
	 * The service documentation URL.
	 */
	private URL serviceDocsURL;


	/**
	 * Prevents public instantiation.
	 */
	private ProviderConfiguration() { }


	/**
	 * Gets the issuer.
	 *
	 * @return The issuer URL.
	 */
	public Issuer getIssuer() {

		return issuer;
	}


	/**
	 * Gets the authorisation endpoint URL.
	 *
	 * @return The authorisation endpoint URL, {@code null} if not 
	 *         specified.
	 */
	public URL getAuthorizationEndpointURL() {

		return authzEndpoint;
	}


	/**
	 * Gets the token endpoint URL.
	 *
	 * @return The token endpoint URL, {@code null} if not specified.
	 */
	public URL getTokenEndpointURL() {

		return tokenEndpoint;
	}


	/**
	 * Gets the UserInfo endpoint URL.
	 *
	 * @return The UserInfo endpoint URL, {@code null} if not specified.
	 */
	public URL getUserInfoEndpointURL() {

		return userInfoEndpoint;
	}


	/**
	 * Gets the client registration endpoint URL.
	 *
	 * @return The client registration endpoint URL, {@code null} if not
	 *         specified.
	 */
	public URL getRegistrationEndpointURL() {

		return regEndpoint;
	}


	/**
	 * Gets the JSON Web Key (JWK) set URL.
	 *
	 * @return The JWK set URL, {@code null} if not specified.
	 */
	public URL getJWKSetURL() {

		return jwkSetURL;
	}


	/**
	 * Gets the encryption JSON Web Key (JWK) set URL.
	 *
	 * @return The encryption JWK set URL, {@code null} if not specified.
	 */
	public URL getEncryptionJWKSetURL() {

		return encryptionJWKSetURL;
	}


	/**
	 * Gets the X.509 certificate URL.
	 *
	 * @return The X.509 certificate URL.
	 */
	public URL getX509URL() {

		return x509URL;
	}


	/**
	 * Gets the encryption X.509 certificate URL.
	 *
	 * @return The encryption X.509 certificate URL, {@code null} if not
	 *         specified.
	 */
	public URL getEncryptionX509URL() {

		return encryptionX509URL;
	}


	/**
	 * Gets the supported scope values.
	 *
	 * @return The supported scope values, {@code null} if not specified.
	 */
	public Scope getScope() {

		return scope;
	}


	/**
	 * Gets the supported response type values.
	 *
	 * @return The supported response type values, {@code null} if not 
	 *         specified.
	 */
	public ResponseTypeSet getResponseTypeSet() {

		return rts;
	}


	/**
	 * Gets the supported Authentication Context Class References (ACRs).
	 *
	 * @return The supported ACRs, {@code null} if not specified.
	 */
	public Set<ACR> getACRs() {

		return acrValues;
	}


	/**
	 * Gets the supported subject types.
	 *
	 * @return The supported subject types.
	 */
	public Set<SubjectType> getSubjectTypes() {

		return subjectTypes;
	}


	/**
	 * Gets the supported token endpoint authentication methods.
	 *
	 * @return The supported token endpoint authentication methods, 
	 *         {@code null} if not specified.
	 */
	public Set<ClientAuthenticationMethod> getTokenEndpointAuthMethods() {

		return tokenEndpointAuthMethods;
	}


	/**
	 * Gets the supported JWS algorithms for the {@code private_key_jwt}
	 * and {@code client_secret_jwt} token endpoint authentication methods.
	 *
	 * @return The supported JWS algorithms, {@code null} if not specified.
	 */
	public Set<JWSAlgorithm> getTokenEndpointJWSAlgs() {

		return tokenEndpointJWSAlgs;
	}


	/**
	 * Gets the supported JWS algorithms for OpenID request objects.
	 *
	 * @return The supported JWS algorithms, {@code null} if not specified.
	 */
	public Set<JWSAlgorithm> getRequestObjectJWSAlgs() {

		return requestObjectJWSAlgs;
	}


	/**
	 * Gets the supported JWE algorithms for OpenID request objects.
	 *
	 * @return The supported JWE algorithms, {@code null} if not specified.
	 */
	public Set<JWEAlgorithm> getRequestObjectJWEAlgs() {

		return requestObjectJWEAlgs;
	}


	/**
	 * Gets the supported encryption methods for OpenID request objects.
	 *
	 * @return The supported encryption methods, {@code null} if not 
	 *         specified.
	 */
	public Set<EncryptionMethod> getRequestObjectJWEEncs() {

		return requestObjectJWEEncs;
	}


	/**
	 * Gets the supported JWS algorithms for ID tokens.
	 *
	 * @return The supported JWS algorithms, {@code null} if not specified.
	 */
	public Set<JWSAlgorithm> getIDTokenJWSAlgs() {

		return idTokenJWSAlgs;
	}


	/**
	 * Gets the supported JWE algorithms for ID tokens.
	 *
	 * @return The supported JWE algorithms, {@code null} if not specified.
	 */
	public Set<JWEAlgorithm> getIDTokenJWEAlgs() {

		return idTokenJWEAlgs;
	}


	/**
	 * Gets the supported encryption methods for ID tokens.
	 *
	 * @return The supported encryption methods, {@code null} if not 
	 *         specified.
	 */
	public Set<EncryptionMethod> getIDTokenJWEEncs() {

		return idTokenJWEEncs;
	}


	/**
	 * Gets the supported JWS algorithms for UserInfo JWTs.
	 *
	 * @return The supported JWS algorithms, {@code null} if not specified.
	 */
	public Set<JWSAlgorithm> getUserInfoJWSAlgs() {

		return idTokenJWSAlgs;
	}


	/**
	 * Gets the supported JWE algorithms for UserInfo JWTs.
	 *
	 * @return The supported JWE algorithms, {@code null} if not specified.
	 */
	public Set<JWEAlgorithm> getUserInfoJWEAlgs() {

		return idTokenJWEAlgs;
	}


	/**
	 * Gets the supported encryption methods for UserInfo JWTs.
	 *
	 * @return The supported encryption methods, {@code null} if not 
	 *         specified.
	 */
	public Set<EncryptionMethod> getUserInfoJWEEncs() {

		return idTokenJWEEncs;
	}


	/**
	 * Gets the supported displays.
	 *
	 * @return The supported displays, {@code null} if not specified.
	 */
	public Set<Display> getDisplays() {

		return displays;
	}


	/**
	 * Gets the names of the supported claims.
	 *
	 * @return The names of the supported claims, {@code null} if not
	 *         specified.
	 */
	public Set<String> getClaims() {

		return claims;
	}


	/**
	 * Gets the service documentation URL.
	 *
	 * @return The service documentation URL, {@code null} if not 
	 *         specified.
	 */
	public URL getServiceDocsURL() {

		return serviceDocsURL;
	}


	/**
	 * Parses a public OpenID Connect provider configuration from the
	 * specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The public OpenID Connect provider configuration.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an
	 *                        OpenID Connect provider configuration.
	 */
	public static ProviderConfiguration parse(final JSONObject jsonObject)
		throws ParseException {

		String version = JSONObjectUtils.getString(jsonObject, "version");

		if(! version.equals(VERSION))
			throw new ParseException("The version must be \"3.0\"");

		ProviderConfiguration config = new ProviderConfiguration();

		URL issuerURL = JSONObjectUtils.getURL(jsonObject, "issuer");

		config.issuer = new Issuer(issuerURL.toString());

		if (jsonObject.containsKey("authorization_endpoint"))
			config.authzEndpoint = JSONObjectUtils.getURL(jsonObject, "authorization_endpoint");

		if (jsonObject.containsKey("token_endpoint"))
			config.tokenEndpoint = JSONObjectUtils.getURL(jsonObject, "token_endpoint");

		if (jsonObject.containsKey("userinfo_endpoint"))
			config.userInfoEndpoint = JSONObjectUtils.getURL(jsonObject, "userinfo_endpoint");

		if (jsonObject.containsKey("registration_endpoint"))
			config.regEndpoint = JSONObjectUtils.getURL(jsonObject, "registration_endpoint");

		if (jsonObject.containsKey("jwk_url"))
			config.jwkSetURL = JSONObjectUtils.getURL(jsonObject, "jwk_url");

		if (jsonObject.containsKey("jwk_encryption_url"))
			config.encryptionJWKSetURL = JSONObjectUtils.getURL(jsonObject, "jwk_encryption_url");

		config.x509URL = JSONObjectUtils.getURL(jsonObject, "x509_url");

		if (jsonObject.containsKey("x509_encryption_url"))
			config.encryptionX509URL = JSONObjectUtils.getURL(jsonObject, "x509_encryption_url");

		if (jsonObject.containsKey("scopes_supported")) {

			if (jsonObject.get("scopes_supported") instanceof String) {

				config.scope = Scope.parse(JSONObjectUtils.getString(jsonObject, "scopes_supported"));	
			}
			else {
				String[] stringArray = JSONObjectUtils.getStringArray(jsonObject, "scopes_supported");

				config.scope = new Scope();

				for (String v: stringArray) {

					if (v != null)
						config.scope.add(new ScopeToken(v));
				}
			}
		}

		if (jsonObject.containsKey("response_types_supported")) {

			if (jsonObject.get("response_types_supported") instanceof String) {

				config.rts = ResponseTypeSet.parse(JSONObjectUtils.getString(jsonObject, "response_types_supported"));
			}
			else {
				String[] stringArray = JSONObjectUtils.getStringArray(jsonObject, "response_types_supported");

				config.rts = new ResponseTypeSet();

				for (String v: stringArray) {

					if (v != null)
						config.rts.add(new ResponseType(v));
				}
			}
		}


		if (jsonObject.containsKey("acr_values_supported")) {

			config.acrValues = new LinkedHashSet<ACR>();

			if (jsonObject.get("acr_values_supported") instanceof String) {

				config.acrValues.add(new ACR(JSONObjectUtils.getString(jsonObject, "acr_values_supported")));
			}
			else {
				String[] stringArray = JSONObjectUtils.getStringArray(jsonObject, "acr_values_supported");

				for (String v: stringArray) {

					if (v != null)
						config.acrValues.add(new ACR(v));
				}
			}
		}


		config.subjectTypes = new LinkedHashSet<SubjectType>();

		if (jsonObject.get("subject_types_supported") instanceof String) {

			config.subjectTypes.add(SubjectType.parse(JSONObjectUtils.getString(jsonObject, "subject_types_supported")));
		}
		else {
			String[] stringArray = JSONObjectUtils.getStringArray(jsonObject, "subject_types_supported");

			for (String v: stringArray) {

				config.subjectTypes.add(SubjectType.parse(v));
			}
		}


		// UserInfo

		if (jsonObject.containsKey("userinfo_signing_alg_values_supported")) {

			config.userInfoJWSAlgs = new LinkedHashSet<JWSAlgorithm>();

			if (jsonObject.get("userinfo_signing_alg_values_supported") instanceof String) {

				config.userInfoJWSAlgs.add(new JWSAlgorithm(JSONObjectUtils.getString(jsonObject, "userinfo_signing_alg_values_supported")));
			}
			else {
				String[] stringArray = JSONObjectUtils.getStringArray(jsonObject, "userinfo_signing_alg_values_supported");

				for (String v: stringArray) {

					if (v != null)
						config.userInfoJWSAlgs.add(new JWSAlgorithm(v));
				}
			}
		}


		if (jsonObject.containsKey("userinfo_encryption_alg_values_supported")) {

			config.userInfoJWEAlgs = new LinkedHashSet<JWEAlgorithm>();

			if (jsonObject.get("userinfo_encryption_alg_values_supported") instanceof String) {

				config.userInfoJWEAlgs.add(new JWEAlgorithm(JSONObjectUtils.getString(jsonObject, "userinfo_encryption_alg_values_supported")));
			}
			else {
				String[] stringArray = JSONObjectUtils.getStringArray(jsonObject, "userinfo_encryption_alg_values_supported");

				for (String v: stringArray) {

					if (v != null)
						config.userInfoJWEAlgs.add(new JWEAlgorithm(v));
				}
			}
		}


		if (jsonObject.containsKey("userinfo_encryption_enc_values_supported")) {

			config.userInfoJWEEncs = new LinkedHashSet<EncryptionMethod>();

			if (jsonObject.get("userinfo_encryption_enc_values_supported") instanceof String) {

				config.userInfoJWEEncs.add(new EncryptionMethod(JSONObjectUtils.getString(jsonObject, "userinfo_encryption_enc_values_supported")));
			}
			else {
				String[] stringArray = JSONObjectUtils.getStringArray(jsonObject, "userinfo_encryption_enc_values_supported");

				for (String v: stringArray) {

					if (v != null)
						config.userInfoJWEEncs.add(new EncryptionMethod(v));
				}
			}
		}


		// ID token

		if (jsonObject.containsKey("id_token_signing_alg_values_supported")) {

			config.idTokenJWSAlgs = new LinkedHashSet<JWSAlgorithm>();

			if (jsonObject.get("id_token_signing_alg_values_supported") instanceof String) {

				config.idTokenJWSAlgs.add(new JWSAlgorithm(JSONObjectUtils.getString(jsonObject, "id_token_signing_alg_values_supported")));
			}
			else {
				String[] stringArray = JSONObjectUtils.getStringArray(jsonObject, "id_token_signing_alg_values_supported");

				for (String v: stringArray) {

					if (v != null)
						config.idTokenJWSAlgs.add(new JWSAlgorithm(v));
				}
			}
		}


		if (jsonObject.containsKey("id_token_encryption_alg_values_supported")) {

			config.idTokenJWEAlgs = new LinkedHashSet<JWEAlgorithm>();

			if (jsonObject.get("id_token_encryption_alg_values_supported") instanceof String) {

				config.idTokenJWEAlgs.add(new JWEAlgorithm(JSONObjectUtils.getString(jsonObject, "id_token_encryption_alg_values_supported")));
			}
			else {
				String[] stringArray = JSONObjectUtils.getStringArray(jsonObject, "id_token_encryption_alg_values_supported");

				for (String v: stringArray) {

					if (v != null)
						config.idTokenJWEAlgs.add(new JWEAlgorithm(v));
				}
			}
		}


		if (jsonObject.containsKey("id_token_encryption_enc_values_supported")) {

			config.idTokenJWEEncs = new LinkedHashSet<EncryptionMethod>();

			if (jsonObject.get("id_token_encryption_enc_values_supported") instanceof String) {

				config.idTokenJWEEncs.add(new EncryptionMethod(JSONObjectUtils.getString(jsonObject, "id_token_encryption_enc_values_supported")));
			}
			else {
				String[] stringArray = JSONObjectUtils.getStringArray(jsonObject, "id_token_encryption_enc_values_supported");

				for (String v: stringArray) {

					if (v != null)
						config.idTokenJWEEncs.add(new EncryptionMethod(v));
				}
			}
		}


		// OpenID request object

		if (jsonObject.containsKey("request_object_signing_alg_values_supported")) {

			config.requestObjectJWSAlgs = new LinkedHashSet<JWSAlgorithm>();

			if (jsonObject.get("request_object_signing_alg_values_supported") instanceof String) {

				config.requestObjectJWSAlgs.add(new JWSAlgorithm(JSONObjectUtils.getString(jsonObject, "request_object_signing_alg_values_supported")));
			}
			else {
				String[] stringArray = JSONObjectUtils.getStringArray(jsonObject, "request_object_signing_alg_values_supported");

				for (String v: stringArray) {

					if (v != null)
						config.requestObjectJWSAlgs.add(new JWSAlgorithm(v));
				}
			}
		}


		if (jsonObject.containsKey("request_object_encryption_alg_values_supported")) {

			config.requestObjectJWEAlgs = new LinkedHashSet<JWEAlgorithm>();

			if (jsonObject.get("request_object_encryption_alg_values_supported") instanceof String) {

				config.requestObjectJWEAlgs.add(new JWEAlgorithm(JSONObjectUtils.getString(jsonObject, "request_object_encryption_alg_values_supported")));
			}
			else {
				String[] stringArray = JSONObjectUtils.getStringArray(jsonObject, "request_object_encryption_alg_values_supported");

				for (String v: stringArray) {

					if (v != null)
						config.requestObjectJWEAlgs.add(new JWEAlgorithm(v));
				}
			}
		}


		if (jsonObject.containsKey("request_object_encryption_enc_values_supported")) {

			config.requestObjectJWEEncs = new LinkedHashSet<EncryptionMethod>();

			if (jsonObject.get("request_object_encryption_enc_values_supported") instanceof String) {

				config.requestObjectJWEEncs.add(new EncryptionMethod(JSONObjectUtils.getString(jsonObject, "request_object_encryption_enc_values_supported")));
			}
			else {
				String[] stringArray = JSONObjectUtils.getStringArray(jsonObject, "request_object_encryption_enc_values_supported");

				for (String v: stringArray) {

					if (v != null)
						config.requestObjectJWEEncs.add(new EncryptionMethod(v));
				}
			}
		}


		if (jsonObject.containsKey("token_endpoint_auth_methods_supported")) {

			config.tokenEndpointAuthMethods = new LinkedHashSet<ClientAuthenticationMethod>();

			if (jsonObject.get("token_endpoint_auth_methods_supported") instanceof String) {

				config.tokenEndpointAuthMethods.add(new ClientAuthenticationMethod(JSONObjectUtils.getString(jsonObject, "token_endpoint_auth_methods_supported")));
			}
			else {
				String[] stringArray = JSONObjectUtils.getStringArray(jsonObject, "token_endpoint_auth_methods_supported");

				for (String v: stringArray) {

					if (v != null)
						config.tokenEndpointAuthMethods.add(new ClientAuthenticationMethod(v));
				}

			}
		}


		if (jsonObject.containsKey("token_endpoint_auth_signing_alg_values_supported")) {

			config.tokenEndpointJWSAlgs = new LinkedHashSet<JWSAlgorithm>();

			if (jsonObject.get("token_endpoint_auth_signing_alg_values_supported") instanceof String) {

				config.tokenEndpointJWSAlgs.add(new JWSAlgorithm(JSONObjectUtils.getString(jsonObject, "token_endpoint_auth_signing_alg_values_supported")));
			}
			else {
				String[] stringArray = JSONObjectUtils.getStringArray(jsonObject, "token_endpoint_auth_signing_alg_values_supported");

				for (String v: stringArray) {

					if (v != null)
						config.tokenEndpointJWSAlgs.add(new JWSAlgorithm(v));
				}
			}
		}


		if (jsonObject.containsKey("display_values_supported")) {

			config.displays = new LinkedHashSet<Display>();

			if (jsonObject.get("display_values_supported") instanceof String) {

				config.displays.add(Display.parse(JSONObjectUtils.getString(jsonObject, "display_values_supported")));
			}
			else {
				String[] stringArray = JSONObjectUtils.getStringArray(jsonObject, "display_values_supported");

				for (String v: stringArray) {

					if (v != null)
						config.displays.add(Display.parse(v));
				}
			}
		}


		if (jsonObject.containsKey("claims_supported")) {

			config.claims = new LinkedHashSet<String>();

			if (jsonObject.get("claims_supported") instanceof String) {

				config.claims.add(JSONObjectUtils.getString(jsonObject, "claims_supported"));
			}
			else {
				String[] stringArray = JSONObjectUtils.getStringArray(jsonObject, "claims_supported");

				for (String v: stringArray) {

					if (v != null)
						config.claims.add(v);
				}
			}
		}


		if (jsonObject.containsKey("service_documentation"))
			config.serviceDocsURL = JSONObjectUtils.getURL(jsonObject, "service_documentation");

		return config;
	}


	/**
	 * Parses a public OpenID Connect provider configuration from the
	 * specified JSON object string.
	 *
	 * @param s The JSON object sting to parse. Must not be {@code null}.
	 *
	 * @return The public OpenID Connect provider configuration.
	 *
	 * @throws ParseException If the JSON object string couldn't be parsed
	 *                        to an OpenID Connect provider configuration.
	 */
	public static ProviderConfiguration parse(final String s)
		throws ParseException {

		return parse(JSONObjectUtils.parseJSONObject(s));
	}
}
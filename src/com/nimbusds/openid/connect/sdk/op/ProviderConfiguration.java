package com.nimbusds.openid.connect.sdk.op;


import java.net.URL;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
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
 * @version $version$ (2013-02-11)
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


	public static ProviderConfiguration parse(final JSONObject jsonObject)
		throws ParseException {


			return null;
	}
}
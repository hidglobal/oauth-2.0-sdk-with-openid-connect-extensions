package com.nimbusds.openid.connect.sdk;


import java.net.MalformedURLException;
import java.net.URL;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.EncryptionMethod;

import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.TypelessAccessToken;

import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;

import com.nimbusds.openid.connect.sdk.claims.ACR;

import com.nimbusds.openid.connect.sdk.rp.ApplicationType;


/**
 * The base class for OpenID Connect client register and update requests.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, section 2.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-28)
 */
class ClientDetailsRequest extends ClientRegistrationRequest {


	/**
	 * The redirect URIs (required).
	 */
	private Set<URL> redirectURIs;


	/**
	 * Administrator contacts for the client (optional).
	 */
	private List<InternetAddress> contacts = null;


	/**
	 * The client application type (optional), defaults to web.
	 */
	private ApplicationType applicationType = ApplicationType.getDefault();


	/**
	 * The client name (optional).
	 */
	private String name = null;


	/**
	 * The client logo (optional).
	 */
	private URL logoURL = null;


	/**
	 * The client policy for use of end-user data (optional).
	 */
	private URL policyURL = null;


	/**
	 * The client terms of service (optional).
	 */
	private URL termsOfServiceURL = null;


	/**
	 * The subject identifier type for responses to this client (optional).
	 */
	private SubjectType subjectType = null;


	/**
	 * Sector identifier HTTPS URL (optional).
	 */
	private URL sectorIDURL = null;


	/**
	 * Token endpoint authentication method (optional), defaults to client
	 * secret basic.
	 */
	private ClientAuthenticationMethod tokenEndpointAuthMethod =
		ClientAuthenticationMethod.getDefault();


	/**
	 * URL for the client's JSON Web Key (JWK) set containing key(s) that
	 * are used in signing Token endpoint requests and OpenID request 
	 * objects (optional). If {@link #encryptionJWKSetURL} is not provided,
	 * also used to encrypt the ID Token and UserInfo endpoint responses 
	 * to the client.
	 */
	private URL jwkSetURL = null;


	/**
	 * URL for the client's JSON Web Key (JWK) set containing key(s) that
	 * are used to encrypt the ID Token and UserInfo endpoint responses to 
	 * the client (optional).
	 */
	private URL encryptionJWKSetURL = null;


	/**
	 * URL for the client's PEM encoded X.509 certificate or certificate 
	 * chain that is used for signing Token endpoint requests and OpenID
	 * request objects (optional). If {@link #encryptionX509URL} is not 
	 * provided, also used to encrypt the ID Token and UserInfo endpoint 
	 * responses to the client.
	 */
	private URL x509URL = null;


	/**
	 * URL for the client's PEM encoded X.509 certificate or certificate
	 * chain that is used to encrypt the ID Token and UserInfo endpoint
	 * responses to the client (optional).
	 */
	private URL encryptionX509URL = null;


	/**
	 * The JSON Web Signature (JWS) algorithm required for the OpenID 
	 * request objects sent by this client (optional).
	 */
	private JWSAlgorithm requestObjectJWSAlg = null;


	/**
	 * The JSON Web Signature (JWS) algorithm required for the ID Tokens
	 * issued to this client (optional).
	 */
	private JWSAlgorithm idTokenJWSAlg = null;


	/**
	 * The JSON Web Encryption (JWE) algorithm required for the ID Tokens
	 * issued to this client (optional).
	 */
	private JWEAlgorithm idTokenJWEAlg = null;


	/**
	 * The encryption method (JWE enc) required for the ID Tokens issued to
	 * this client (optional).
	 */
	private EncryptionMethod idTokenJWEEnc = null;


	/**
	 * The JSON Web Signature (JWS) algorithm required for the UserInfo
	 * responses to this client (optional).
	 */
	private JWSAlgorithm userInfoJWSAlg = null;


	/**
	 * The JSON Web Encryption (JWE) algorithm required for the UserInfo
	 * responses to this client (optional).
	 */
	private JWEAlgorithm userInfoJWEAlg = null;


	/**
	 * The encryption method (JWE enc) required for the UserInfo responses
	 * to this client (optional).
	 */
	private EncryptionMethod userInfoJWEEnc = null;


	/**
	 * The default max authentication age, in seconds (optional). If not 
	 * specified 0.
	 */
	private int defaultMaxAge = 0;


	/**
	 * If {@code true} the {@code auth_time} claim in the ID Token is
	 * required by default (optional).
	 */
	private boolean requireAuthTime = false;


	/**
	 * The default Authentication Context Class Reference (ACR) (optional).
	 */
	private ACR defaultACR = null;


	/**
	 * Authorisation server initiated login HTTPS URL (optional).
	 */
	private URL initiateLoginURI = null;


	/**
	 * Logout redirect URL (optional).
	 */
	private URL postLogoutRedirectURI = null;


	/**
	 * Creates a new OpenID Connect client details request.
	 *
	 * @param operation    The client registration operation. Must be 
	 *                     {@link ClientRegistrationOperation#CLIENT_REGISTER} 
	 *                     or {@link ClientRegistrationOperation#CLIENT_UPDATE}.
	 *                     Must not be {@code null}.
	 * @param redirectURIs The client redirect URIs. The set must not be
	 *                     {@code null} and must include at least one URL.
	 */
	protected ClientDetailsRequest(final ClientRegistrationOperation operation,
		                       final Set<URL> redirectURIs) {

		super(operation);

		if (! operation.equals(ClientRegistrationOperation.CLIENT_REGISTER) &&
		    ! operation.equals(ClientRegistrationOperation.CLIENT_UPDATE))
			throw new IllegalArgumentException("The client registration operation must be CLIENT_REGISTER or CLIENT_UPDATE");


		if (redirectURIs == null)
			throw new IllegalArgumentException("The redirect URIs must not be null");

		if (redirectURIs.isEmpty())
			throw new IllegalArgumentException("At least one redirect URI must be specified");

		this.redirectURIs = redirectURIs;
	}


	/**
	 * Creates a new OpenID Connect client details request.
	 *
	 * @param operation   The client registration operation. Must be 
	 *                    {@link ClientRegistrationOperation#CLIENT_REGISTER} 
	 *                    or {@link ClientRegistrationOperation#CLIENT_UPDATE}.
	 *                    Must not be {@code null}.
	 * @param redirectURI The client redirect URI. Must not be 
	 *                    {@code null}.
	 */
	protected ClientDetailsRequest(final ClientRegistrationOperation operation,
		                       final URL redirectURI) {

		this(operation, createNewSingleURLSet(redirectURI));
	}


	/**
	 * Creates a new set with the specified URL.
	 *
	 * @param url The URL to add to the set. Must not be {@code null}.
	 *
	 * @return The set with the specified URL.
	 */
	private static Set<URL> createNewSingleURLSet(final URL url) {

		Set<URL> set = new HashSet<URL>();
		set.add(url);
		return set;
	}


	/**
	 * Gets the redirect URIs for the client. Corresponds to the
	 * {@code redirect_uris} parameter.
	 *
	 * @return The redirect URIs for the client.
	 */
	public Set<URL> getRedirectURIs() {
	
		return redirectURIs;
	}


	/**
	 * Gets the administrator contacts for the client. Corresponds to the
	 * {@code contacts} parameter.
	 *
	 * @return The administrator contacts for the client, {@code null} if
	 *         none.
	 */
	public List<InternetAddress> getContacts() {

		return contacts;
	}


	/**
	 * Sets the administrator contacts for the client. Corresponds to the
	 * {@code contacts} parameter.
	 *
	 * @param contacts The administrator contacts for the client, 
	 *                 {@code null} if none.
	 */
	public void setContacts(final List<InternetAddress> contacts) {

		this.contacts = contacts;
	}


	/**
	 * Gets the client application type. Corresponds to the
	 * {@code application_type} parameter.
	 *
	 * @return The client application type, defaults to {@code WEB} if not 
	 *         specified.
	 */
	public ApplicationType getApplicationType() {

		if (applicationType == null)
			return ApplicationType.getDefault();
		else
			return applicationType;
	}


	/**
	 * Sets the client application type. Corresponds to the
	 * {@code application_type} parameter.
	 *
	 * @param applicationType The client application type, {@code null} if 
	 *                        not specified.
	 */
	public void setApplicationType(final ApplicationType applicationType) {

		this.applicationType = applicationType;
	}


	/**
	 * Gets the client name. Corresponds to the {@code client_name} 
	 * parameter.
	 *
	 * @return The client name, {@code null} if not specified.
	 */
	public String getName() {

		return name;
	}


	/**
	 * Sets the client name. Corresponds to the {@code client_name} 
	 * parameter.
	 *
	 * @param name The client name, {@code null} if not specified.
	 */
	public void setName(final String name) {

		this.name = name;
	}


	/**
	 * Gets the client logo URL. Corresponds to the {@code logo_url} 
	 * parameter.
	 *
	 * @return The client logo URL, {@code null} if not specified.
	 */
	public URL getLogoURL() {

		return logoURL;
	}


	/**
	 * Sets the client logo URL. Corresponds to the {@code logo_url} 
	 * parameter.
	 *
	 * @param logoURL The client logo URL, {@code null} if not specified.
	 */
	public void setLogoURL(final URL logoURL) {

		this.logoURL = logoURL;
	}


	/**
	 * Gets the client policy for use of end-user data. Corresponds to the
	 * {@code policy_url} parameter.
	 *
	 * @return The policy URL, {@code null} if not specified.
	 */
	public URL getPolicyURL() {

		return policyURL;
	}


	/**
	 * Sets the client policy for use of end-user data. Corresponds to the
	 * {@code policy_url} parameter.
	 *
	 * @param policyURL The policy URL, {@code null} if not specified.
	 */
	public void setPolicyURL(final URL policyURL) {

		this.policyURL = policyURL;
	}


	/**
	 * Gets the client terms of service. Corresponds to the {@code tos_url}
	 * parameter.
	 *
	 * @return The terms of service URL, {@code null} if not specified.
	 */
	public URL getTermsOfServiceURL() {

		return termsOfServiceURL;
	}


	/**
	 * Sets the client terms of service. Corresponds to the {@code tos_url}
	 * parameter.
	 *
	 * @param termsOfServiceURL The terms of service URL, {@code null} if 
	 *                          not specified.
	 */
	public void setTermsOfServiceURL(final URL termsOfServiceURL) {

		this.termsOfServiceURL = termsOfServiceURL;
	}


	/**
	 * Gets the subject identifier type for responses to the client. 
	 * Corresponds to the {@code subject_type} parameter.
	 *
	 * @return The subject identifier type, {@code null} if not specified.
	 */
	public SubjectType getSubjectType() {

		return subjectType;
	}


	/**
	 * Sets the subject identifier type for responses to this client. 
	 * Corresponds to the {@code subject_type} parameter.
	 *
	 * @param subjectType The subject identifier type, {@code null} if not 
	 *                    specified.
	 */
	public void setSubjectType(final SubjectType subjectType) {

		this.subjectType = subjectType;
	}


	/**
	 * Gets the sector identifier URL. Corresponds to the 
	 * {@code sector_identifier_url} parameter.
	 *
	 * @return The sector identifier URL, {@code null} if not specified.
	 */
	public URL getSectorIDURL() {

		return sectorIDURL;
	}


	/**
	 * Sets the sector identifier URL. Corresponds to the 
	 * {@code sector_identifier_url} parameter.
	 *
	 * @param sectorIDURL The sector identifier URL, {@code null} if not 
	 *                    specified.
	 */
	public void setSectorIDURL(final URL sectorIDURL) {

		this.sectorIDURL = sectorIDURL;
	}


	/**
	 * Gets the Token endpoint authentication method. Corresponds to the
	 * {@code token_endpoint_auth_method} parameter.
	 *
	 * @return The Token endpoint authentication method, defaults to client
	 *         secret basic if not specified.
	 */
	public ClientAuthenticationMethod getTokenEndpointAuthMethod() {

		if (tokenEndpointAuthMethod == null)
			return ClientAuthenticationMethod.getDefault();

		return tokenEndpointAuthMethod;
	}


	/**
	 * Sets the Token endpoint authentication method. Corresponds to the
	 * {@code token_endpoint_auth_method} parameter.
	 *
	 * @param tokenEndpointAuthMethod The Token endpoint authentication 
	 *                                method, {@code null} if not 
	 *                                specified.
	 */
	public void setTokenEndpointAuthMethod(final ClientAuthenticationMethod tokenEndpointAuthMethod) {

		this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
	}


	/**
	 * Gets the URL for the client's JSON Web Key (JWK) set containing
	 * key(s) that are used in signing Token endpoint requests and OpenID 
	 * request objects. If {@link #getEncryptionJWKSetURL} if not provided, 
	 * also used to encrypt the ID Token and UserInfo endpoint responses to
	 * the client. Corresponds to the {@code jwk_url} parameter.
	 *
	 * @return The JWK set URL, {@code null} if not specified.
	 */
	public URL getJWKSetURL() {

		return jwkSetURL;
	}


	/**
	 * Sets the URL for the client's JSON Web Key (JWK) set containing 
	 * key(s) that are used in signing Token endpoint requests and OpenID 
	 * request objects. If {@link #getEncryptionJWKSetURL} if not provided, 
	 * also used to encrypt the ID Token and UserInfo endpoint responses to 
	 * the client. Corresponds to the {@code jwk_url} parameter.
	 *
	 * @param jwkSetURL The JWK set URL, {@code null} if not specified.
	 */
	public void setJWKSetURL(final URL jwkSetURL) {

		this.jwkSetURL = jwkSetURL;
	}


	/**
	 * Gets the URL for the client's JSON Web Key (JWK) set containing 
	 * key(s) that are used to encrypt the ID Token and UserInfo endpoint 
	 * responses to the client. Corresponds to the 
	 * {@code jwk_encryption_url} parameter.
	 *
	 * @return The encryption JWK set URL, {@code null} if not specified.
	 */
	public URL getEncryptionJWKSetURL() {

		return encryptionJWKSetURL;
	}


	/**
	 * Sets the URL for the client's JSON Web Key (JWK) set containing 
	 * key(s) that are used to encrypt the ID Token and UserInfo endpoint 
	 * responses to the client. Corresponds to the 
	 * {@code jwk_encryption_url} parameter.
	 *
	 * @param encryptionJWKSetURL The encryption JWK set URL, {@code null} 
	 *                            if not specified.
	 */
	public void setEncrytionJWKSetURL(final URL encryptionJWKSetURL) {

		this.encryptionJWKSetURL = encryptionJWKSetURL;
	}


	/**
	 * Gets the URL for the client's PEM encoded X.509 certificate or 
	 * certificate chain that is used for signing Token endpoint requests 
	 * and OpenID request objects. If {@link #getEncryptionX509URL} is not 
	 * provided, also used to encrypt the ID Token and UserInfo endpoint 
	 * responses to the client. Corresponds to the {@code x509_url}
	 * parameter.
	 *
	 * @return The X.509 certificate URL, {@code null} if not specified.
	 */
	public URL getX509URL() {

		return x509URL;
	}


	/**
	 * Sets the URL for the client's PEM encoded X.509 certificate or 
	 * certificate chain that is used for signing Token endpoint requests 
	 * and OpenID request objects. If {@link #getEncryptionX509URL} is not 
	 * provided, also used to encrypt the ID Token and UserInfo endpoint 
	 * responses to the client. Corresponds to the {@code x509_url}
	 * parameter.
	 *
	 * @param x509URL The X.509 certificate URL, {@code null} if not 
	 *                specified.
	 */
	public void setX509URL(final URL x509URL) {

		this.x509URL = x509URL;
	}


	/**
	 * Gets the URL for the client's PEM encoded X.509 certificate or 
	 * certificate chain that is used to encrypt the ID Token and UserInfo 
	 * endpoint responses to the client. Corresponds to the 
	 * {@code x509_encryption_url} parameter.
	 *
	 * @return The encryption X.509 certificate URL, {@code null} if not
	 *         specified.
	 */
	public URL getEncryptionX509URL() {

		return encryptionX509URL;
	}


	/**
	 * Sets the URL for the client's PEM encoded X.509 certificate or 
	 * certificate chain that is used to encrypt the ID Token and UserInfo 
	 * endpoint responses to the client. Corresponds to the 
	 * {@code x509_encryption_url} parameter.
	 *
	 * @param encryptionX509URL The encryption X.509 certificate URL, 
	 *                          {@code null} if not specified.
	 */
	public void setEncryptionX509URL(final URL encryptionX509URL) {

		this.encryptionX509URL = encryptionX509URL;
	}


	/**
	 * Gets the JSON Web Signature (JWS) algorithm required for the OpenID 
	 * request objects sent by this client. Corresponds to the
	 * {@code request_object_signing_alg} parameter.
	 *
	 * @return The JWS algorithm, {@code null} if not specified.
	 */
	public JWSAlgorithm getRequestObjectJWSAlgorithm() {

		return requestObjectJWSAlg;
	}


	/**
	 * Sets the JSON Web Signature (JWS) algorithm required for the OpenID 
	 * request objects sent by this client. Corresponds to the
	 * {@code request_object_signing_alg} parameter.
	 *
	 * @param requestObjectJWSAlg The JWS algorithm, {@code null} if not 
	 *                            specified.
	 */
	public void setRequestObjectJWSAlgorithm(final JWSAlgorithm requestObjectJWSAlg) {

		this.requestObjectJWSAlg = requestObjectJWSAlg;
	}


	/**
	 * Gets the JSON Web Signature (JWS) algorithm required for the ID 
	 * Tokens issued to this client. Corresponds to the 
	 * {@code id_token_signed_response_alg}.
	 *
	 * @return The JWS algorithm, {@code null} if not specified.
	 */
	public JWSAlgorithm getIDTokenJWSAlgorithm() {

		return idTokenJWSAlg;
	}


	/**
	 * Sets the JSON Web Signature (JWS) algorithm required for the ID 
	 * Tokens issued to this client. Corresponds to the 
	 * {@code id_token_signed_response_alg}.
	 *
	 * @param idTokenJWSAlg The JWS algorithm, {@code null} if not 
	 *                      specified.
	 */
	public void setIDTokenJWSAlgorithm(final JWSAlgorithm idTokenJWSAlg) {

		this.idTokenJWSAlg = idTokenJWSAlg;
	}


	/**
	 * Gets the JSON Web Encryption (JWE) algorithm required for the ID 
	 * Tokens issued to this client. Corresponds to the 
	 * {@code id_token_encrypted_response_alg} parameter.
	 *
	 * @return The JWE algorithm, {@code null} if not specified.
	 */
	public JWEAlgorithm getIDTokenJWEAlgorithm() {

		return idTokenJWEAlg;
	}


	/**
	 * Sets the JSON Web Encryption (JWE) algorithm required for the ID 
	 * Tokens issued to this client. Corresponds to the 
	 * {@code id_token_encrypted_response_alg} parameter.
	 *
	 * @param idTokenJWEAlg The JWE algorithm, {@code null} if not 
	 *                      specified.
	 */
	public void setIDTokenJWEAlgorithm(final JWEAlgorithm idTokenJWEAlg) {

		this.idTokenJWEAlg = idTokenJWEAlg;
	}


	/**
	 * Gets the encryption method (JWE enc) required for the ID Tokens 
	 * issued to this client. Corresponds to the 
	 * {@code id_token_encrypted_response_enc} parameter.
	 *
	 * @return The JWE encryption method, {@code null} if not specified.
	 */
	public EncryptionMethod getIDTokenJWEEncryptionMethod() {

		return idTokenJWEEnc;
	}


	/**
	 * Sets the encryption method (JWE enc) required for the ID Tokens 
	 * issued to this client. Corresponds to the 
	 * {@code id_token_encrypted_response_enc} parameter.
	 *
	 * @param idTokenJWEEnc The JWE encryption method, {@code null} if not 
	 *                      specified.
	 */
	public void setIDTokenJWEEncryptionMethod(final EncryptionMethod idTokenJWEEnc) {

		this.idTokenJWEEnc = idTokenJWEEnc;
	}


	/**
	 * Gets the JSON Web Signature (JWS) algorithm required for the 
	 * UserInfo responses to this client. Corresponds to the
	 * {@code userinfo_signed_response_alg} parameter.
	 *
	 * @return The JWS algorithm, {@code null} if not specified.
	 */
	public JWSAlgorithm getUserInfoJWSAlgorithm() {

		return userInfoJWSAlg;
	}


	/**
	 * Sets the JSON Web Signature (JWS) algorithm required for the 
	 * UserInfo responses to this client. Corresponds to the
	 * {@code userinfo_signed_response_alg} parameter.
	 *
	 * @param userInfoJWSAlg The JWS algorithm, {@code null} if not 
	 *                       specified.
	 */
	public void setUserInfoJWSAlgorithm(final JWSAlgorithm userInfoJWSAlg) {

		this.userInfoJWSAlg = userInfoJWSAlg;
	}


	/**
	 * Gets the JSON Web Encryption (JWE) algorithm required for the 
	 * UserInfo responses to this client. Corresponds to the
	 * {@code userinfo_encrypted_response_alg} parameter.
	 *
	 * @return The JWE algorithm, {@code null} if not specified.
	 */
	public JWEAlgorithm getUserInfoJWEAlgorithm() {

		return userInfoJWEAlg;
	}


	/**
	 * Sets the JSON Web Encryption (JWE) algorithm required for the 
	 * UserInfo responses to this client. Corresponds to the
	 * {@code userinfo_encrypted_response_alg} parameter.
	 *
	 * @param userInfoJWEAlg The JWE algorithm, {@code null} if not
	 *                       specified.
	 */
	public void setUserInfoJWEAlgorithm(final JWEAlgorithm userInfoJWEAlg) {

		this.userInfoJWEAlg = userInfoJWEAlg;
	}


	/**
	 * Gets the encryption method (JWE enc) required for the UserInfo 
	 * responses to this client. Corresponds to the
	 * {@code userinfo_encrypted_response_enc} parameter.
	 *
	 * @return The JWE encryption method, {@code null} if not specified.
	 */
	public EncryptionMethod getUserInfoJWEEncryptionMethod() {

		return userInfoJWEEnc;
	}


	/**
	 * Sets the encryption method (JWE enc) required for the UserInfo 
	 * responses to this client. Corresponds to the
	 * {@code userinfo_encrypted_response_enc} parameter.
	 *
	 * @param userInfoJWEEnc The JWE encryption method, {@code null} if not 
	 *                       specified.
	 */
	public void setUserInfoJWEEncryptionMethod(final EncryptionMethod userInfoJWEEnc) {

		this.userInfoJWEEnc = userInfoJWEEnc;
	}


	/**
	 * Gets the default maximum authentication age. Corresponds to the 
	 * {@code default_max_age} parameter.
	 *
	 * @return The default max authentication age, in seconds. If not
	 *         specified 0.
	 */
	public int getDefaultMaxAge() {

		return defaultMaxAge;
	}


	/**
	 * Sets the default maximum authentication age. Corresponds to the 
	 * {@code default_max_age} parameter.
	 *
	 * @param defaultMaxAge The default max authentication age, in seconds.
	 *                      If not specified 0.
	 */
	public void setDefaultMaxAge(final int defaultMaxAge) {

		this.defaultMaxAge = defaultMaxAge;
	}


	/**
	 * Gets the default requirement for the {@code auth_time} claim in the
	 * ID Token. Corresponds to the {@code require_auth_time} parameter.
	 *
	 * @return If {@code true} the {@code auth_Time} claim in the ID Token 
	 *         is required by default.
	 */
	public boolean requireAuthTime() {

		return requireAuthTime;
	}


	/**
	 * Sets the default requirement for the {@code auth_time} claim in the
	 * ID Token. Corresponds to the {@code require_auth_time} parameter.
	 *
	 * @param requireAuthTime If {@code true} the {@code auth_Time} claim 
	 *                        in the ID Token is required by default.
	 */
	public void requireAuthTime(final boolean requireAuthTime) {

		this.requireAuthTime = requireAuthTime;
	}


	/**
	 * Gets the default Authentication Context Class Reference (ACR).
	 * Corresponds to the {@code default_acr} parameter.
	 *
	 * @return The default ACR, {@code null} if not specified.
	 */
	public ACR getDefaultACR() {

		return defaultACR;
	}


	/**
	 * Sets the default Authentication Context Class Reference (ACR).
	 * Corresponds to the {@code default_acr} parameter.
	 *
	 * @param defaultACR The default ACR, {@code null} if not specified.
	 */
	public void setDefaultACR(final ACR defaultACR) {

		this.defaultACR = defaultACR;
	}


	/**
	 * Gets the authorisation server initiated login HTTPS URL. Corresponds
	 * to the {@code initiate_login_uri} parameter.
	 *
	 * @return The login URL, {@code null} if not specified.
	 */
	public URL getInitiateLoginURI() {

		return initiateLoginURI;
	}


	/**
	 * Sets the authorisation server initiated login HTTPS URL. Corresponds
	 * to the {@code initiate_login_uri} parameter.
	 *
	 * @param initiateLoginURI The login URL, {@code null} if not 
	 *                         specified.
	 */
	public void setInitiateLoginURI(final URL initiateLoginURI) {

		this.initiateLoginURI = initiateLoginURI;
	}


	/**
	 * Gets the post logout redirect URL. Corresponds to the 
	 * {@code post_logout_redirect_url} parameter.
	 *
	 * @return The post logout redirect URL, {@code null} if not specified.
	 */
	public URL getPostLogoutRedirectURI() {

		return postLogoutRedirectURI;
	}


	/**
	 * Sets the post logout redirect URL. Corresponds to the 
	 * {@code post_logout_redirect_url} parameter.
	 *
	 * @param postLogoutRedirectURI The post logout redirect URL, 
	 *                              {@code null} if not specified.
	 */
	public void setPostLogoutRedirectURI(final URL postLogoutRedirectURI) {

		this.postLogoutRedirectURI = postLogoutRedirectURI;
	}


	/**
	 * Applies the optional parameters from the specified parameters map to
	 * this request.
	 *
	 * @param params The parameter map to apply. Must not be {@code null}.
	 *
	 * @throws ParseException If the parameter map couldn't be applied.
	 */
	protected void applyOptionalParameters(final Map<String,String> params)
		throws ParseException {

		String v = null;

		// Access token inlined?
		v = params.get("access_token");

		if (StringUtils.isDefined(v))
			setAccessToken(new TypelessAccessToken(v));


		setApplicationType(parseEnum("application_type", ApplicationType.class, params));

		setContacts(parseEmailList("contacts", params));

		setName(params.get("client_name"));

		setLogoURL(parseURL("logo_url", params));

		setPolicyURL(parseURL("policy_url", params));

		setTermsOfServiceURL(parseURL(("tos_url"), params));

		setSubjectType(parseEnum("subject_type", SubjectType.class, params));

		setSectorIDURL(parseURL("sector_identifier_url", params));


		v = params.get("token_endpoint_auth_method");

		if (StringUtils.isDefined(v))
			setTokenEndpointAuthMethod(new ClientAuthenticationMethod(v));


		setJWKSetURL(parseURL("jwk_url", params));

		setEncrytionJWKSetURL(parseURL("jwk_encryption_url", params));

		setX509URL(parseURL("x509_url", params));

		setEncryptionX509URL(parseURL("x509_encryption_url", params));


		v = params.get("request_object_signing_alg");

		if (StringUtils.isDefined(v))
			setRequestObjectJWSAlgorithm(JWSAlgorithm.parse(v));


		v = params.get("id_token_signed_response_alg");

		if (StringUtils.isDefined(v))
			setIDTokenJWSAlgorithm(JWSAlgorithm.parse(v));


		v = params.get("id_token_encrypted_response_alg");

		if (StringUtils.isDefined(v))
			setIDTokenJWEAlgorithm(JWEAlgorithm.parse(v));


		v = params.get("id_token_encrypted_response_enc");

		if (StringUtils.isDefined(v))
			setIDTokenJWEEncryptionMethod(EncryptionMethod.parse(v));


		v = params.get("userinfo_signed_response_alg");

		if (StringUtils.isDefined(v))
			setUserInfoJWSAlgorithm(JWSAlgorithm.parse(v));


		v = params.get("userinfo_encrypted_response_alg");

		if (StringUtils.isDefined(v))
			setUserInfoJWEAlgorithm(JWEAlgorithm.parse(v));


		v = params.get("userinfo_encrypted_response_enc");

		if (StringUtils.isDefined(v))
			setUserInfoJWEEncryptionMethod(EncryptionMethod.parse(v));


		setDefaultMaxAge(parsePositiveInt("default_max_age", params));


		v = params.get("require_auth_time");

		if (StringUtils.isDefined(v)) {

			if (v.equalsIgnoreCase("true"))
				requireAuthTime(true);

			else if (v.equalsIgnoreCase("false"))
				requireAuthTime(false);

			else 
				throw new ParseException("Invalid \"require_auth_time\" parameter, must be true or false",
				                         OIDCError.INVALID_CONFIGURATION_PARAMETER);
		}


		v = params.get("default_acr");

		if (StringUtils.isDefined(v))
			setDefaultACR(new ACR(v));


		setInitiateLoginURI(parseURL("initiate_login_uri", params));


		setPostLogoutRedirectURI(parseURL("post_logout_redirect_url", params));
	}


	@Override
	public Map<String,String> toParameters(final boolean includeAccessToken) {

		Map<String,String> params = super.toParameters(includeAccessToken);

		StringBuilder urisBuf = new StringBuilder();

		for (URL url: redirectURIs) {

			if (urisBuf.length() > 0)
				urisBuf.append(' ');

			urisBuf.append(url.toString());
		}

		params.put("redirect_uris", urisBuf.toString());


		if (contacts != null && ! contacts.isEmpty()) {

			StringBuilder emailBuf = new StringBuilder();

			for (InternetAddress email: contacts) {

				if (emailBuf.length() > 0)
					emailBuf.append(' ');

				emailBuf.append(email.getAddress());
			}

			params.put("contacts", emailBuf.toString());
		}


		params.put("application_type", getApplicationType().toString());


		if (name != null)
			params.put("client_name", name);


		if (logoURL != null)
			params.put("logo_url", logoURL.toString());


		if (policyURL != null)
			params.put("policy_url", policyURL.toString());


		if (termsOfServiceURL != null)
			params.put("tos_url", termsOfServiceURL.toString());


		if (subjectType != null)
			params.put("subject_type", subjectType.toString());


		if (sectorIDURL != null)
			params.put("sector_identifier_url", sectorIDURL.toString());


		params.put("token_endpoint_auth_method", getTokenEndpointAuthMethod().toString());


		if (jwkSetURL != null)
			params.put("jwk_url", jwkSetURL.toString());


		if (encryptionJWKSetURL != null)
			params.put("jwk_encryption_url", encryptionJWKSetURL.toString());


		if (x509URL != null)
			params.put("x509_url", x509URL.toString());


		if (encryptionX509URL != null)
			params.put("x509_encryption_url", encryptionX509URL.toString());


		if (requestObjectJWSAlg != null)
			params.put("request_object_signing_alg", requestObjectJWSAlg.toString());


		if (idTokenJWSAlg != null)
			params.put("id_token_signed_response_alg", idTokenJWSAlg.toString());


		if (idTokenJWEAlg != null)
			params.put("id_token_encrypted_response_alg", idTokenJWEAlg.toString());


		if (idTokenJWEEnc != null)
			params.put("id_token_encrypted_response_enc", idTokenJWEEnc.toString());


		if (userInfoJWSAlg != null)
			params.put("userinfo_signed_response_alg", userInfoJWSAlg.toString());


		if (userInfoJWEAlg != null)
			params.put("userinfo_encrypted_response_alg", userInfoJWEAlg.toString());


		if (userInfoJWEEnc != null)
			params.put("userinfo_encrypted_response_enc", userInfoJWEEnc.toString());


		if (defaultMaxAge > 0)
			params.put("default_max_age", new Integer(defaultMaxAge).toString());


		if (requireAuthTime)
			params.put("require_auth_time", new Boolean(requireAuthTime).toString());


		if (defaultACR != null)
			params.put("default_acr", defaultACR.toString());


		if (initiateLoginURI != null)
			params.put("initiate_login_uri", initiateLoginURI.toString());


		if (postLogoutRedirectURI != null)
			params.put("post_logout_redirect_url", postLogoutRedirectURI.toString());

		return params;
	}


	/**
	 * Parses an OpenID Connect client details request from the specified 
	 * HTTP POST request.
	 *
	 * <p>Example HTTP request (GET):
	 *
	 * <pre>
	 * POST /connect/register HTTP/1.1
	 * Content-Type: application/x-www-form-urlencoded
	 * Host: server.example.com
	 * Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJ ...
 	 * 
	 * operation=client_register
	 * &amp;application_type=web
	 * &amp;redirect_uris=https://client.example.org/callback%20https://client.example.org/callback2
	 * &amp;client_name=My%20Example%20
	 * &amp;client_name%23ja-Jpan-JP=ワタシ用の例
	 * &amp;logo_url=https://client.example.org/logo.png
	 * &amp;subject_type=pairwise
	 * &amp;sector_identifier_url=https://othercompany.com/file_of_redirect_uris.json
	 * &amp;token_endpoint_auth_method=client_secret_basic
	 * &amp;jwk_url=https://client.example.org/my_rsa_public_key.jwk
	 * &amp;userinfo_encrypted_response_alg=RSA1_5
	 * &amp;userinfo_encrypted_response_enc=A128CBC+HS256
	 * </pre>
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The client registration request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a 
	 *                        client registration request.
	 */
	public static ClientDetailsRequest parse(final HTTPRequest httpRequest)
		throws ParseException {

		if (! httpRequest.getMethod().equals(HTTPRequest.Method.POST)) 
			throw new ParseException("Invalid client registration request, must be sent by HTTP POST",
				                 OAuth2Error.INVALID_REQUEST);

		if (httpRequest.getQuery() == null)
			throw new ParseException("Missing client registration parameters",
				                 OAuth2Error.INVALID_REQUEST);
		

		// Decode and parse POST parameters
		Map <String,String> params = URLUtils.parseParameters(httpRequest.getQuery());
		
		
		// Mandatory params

		ClientRegistrationOperation operation = ClientRegistrationOperation.parse(params);

		if (operation != ClientRegistrationOperation.CLIENT_REGISTER &&
		    operation != ClientRegistrationOperation.CLIENT_UPDATE      )
			throw new ParseException("Invalid \"operation\" parameter", 
					                 OIDCError.INVALID_OPERATION);

		String v = params.get("redirect_uris");
		
		if (StringUtils.isUndefined(v))
			throw new ParseException("Missing \"redirect_uris\" parameter", 
				                 OIDCError.INVALID_REDIRECT_URI);
		
		
		Set<URL> redirectURIs = new HashSet<URL>();

		for (String uriString: v.split(" ")) {

			try {
				redirectURIs.add(new URL(uriString));

			} catch (MalformedURLException e) {

				throw new ParseException("Invalid \"redirect_uris\" parameter: " +
					                  e.getMessage(),
					                  OIDCError.INVALID_REDIRECT_URI);
			}
		}


		ClientDetailsRequest req = new ClientDetailsRequest(operation, redirectURIs);

		// Parse optional params
		req.applyOptionalParameters(params);


		// Access token in header?
		if (StringUtils.isDefined(httpRequest.getAuthorization()))			
			req.setAccessToken(AccessToken.parse(httpRequest.getAuthorization()));
		
		return req;
	}


	/**
	 * Parses an URL configuration parameter.
	 *
	 * @param name   The parameter name. The corresponding parameter value 
	 *               must be an URL or undefined ({@code null}). The  
	 *               parameter name itself must not be {@code null}.
	 * @param params The parameter map. Must not be {@code null}.
	 *
	 * @return The URL, {@code null} if the parameter is not specified.
	 *
	 * @throws ParseException On a invalid URL syntax.
	 */
	private static URL parseURL(final String name, final Map<String,String> params)
		throws ParseException {

		String value = params.get(name);

		if (StringUtils.isUndefined(value))
			return null;

		try {
			return new URL(value);

		} catch (MalformedURLException e) {

			throw new ParseException("Invalid \"" + name + "\" parameter: " + e.getMessage(),
				                 OIDCError.INVALID_CONFIGURATION_PARAMETER);
		}
	}


	/**
	 * Parses an integer (positive value) configuration parameter.
	 *
	 * @param name   The parameter name. The corresponding parameter value 
	 *               must be a positive integer or undefined 
	 *               ({@code null}). The  parameter name itself must not be
	 *               {@code null}.
	 * @param params The parameter map. Must not be {@code null}.
	 *
	 * @return The positive integer, zero if the parameter is not
	 *         specified.
	 *
	 * @throws ParseException On a invalid integer syntax or non-positive
	 *                        value.
	 */
	private static int parsePositiveInt(final String name, final Map<String,String> params)
		throws ParseException {

		String value = params.get(name);

		if (StringUtils.isUndefined(value))
			return 0;

		int intValue = 0;

		try {
			intValue = Integer.parseInt(value);

		} catch (NumberFormatException e) {

			throw new ParseException("Invalid \"" + name + "\" parameter: " + 
					         e.getMessage(),
					         OIDCError.INVALID_CONFIGURATION_PARAMETER);
		}

		if (intValue < 1)
			throw new ParseException("Invalid \"" + name + "\" parameter: Must be positive integer",
				                 OIDCError.INVALID_CONFIGURATION_PARAMETER);
	
		return intValue;
	}


	/**
	 * Parses an email list configuration parameter.
	 *
	 * @param name   The parameter name. The corresponding parameter value 
	 *               must be a list or one or more space delimited
	 *               email addresses, or undefined ({@code null}). The  
	 *               parameter name itself must not be {@code null}.
	 * @param params The parameter map. Must not be {@code null}.
	 *
	 * @return The email list, {@code null} if the parameter is not
	 *         specified.
	 *
	 * @throws ParseException On a invalid email syntax.
	 */
	private static List<InternetAddress> parseEmailList(final String name, final Map<String,String> params)
		throws ParseException {

		String value = params.get(name);

		if (StringUtils.isUndefined(value))
			return null;

		List<InternetAddress> emailList = new LinkedList<InternetAddress>();

		for (String emailString: value.split(" ")) {

			try {
				emailList.add(new InternetAddress(emailString));

			} catch (AddressException e) {

				throw new ParseException("Invalid \"" + name + "\" parameter: " +
						         e.getMessage(),
						         OIDCError.INVALID_CONFIGURATION_PARAMETER);
			}
		}

		return emailList;
	}
}
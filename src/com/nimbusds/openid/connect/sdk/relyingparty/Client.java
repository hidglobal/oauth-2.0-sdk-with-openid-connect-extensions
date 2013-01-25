package com.nimbusds.openid.connect.sdk.relyingparty;


import java.net.URL;

import java.util.List;
import java.util.Set;

import javax.mail.internet.InternetAddress;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;

import com.nimbusds.openid.connect.sdk.SubjectType;

import com.nimbusds.openid.connect.sdk.claims.ACR;


/**
 * OpenID Connect client details.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, section 2.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-25)
 */
public class Client {


	/**
	 * The registered client ID.
	 */
	private final ClientID id;
	
	
	/**
	 * Redirect URIs.
	 */
	private Set<URL> redirectURIs = null;


	/**
	 * Administrator contacts for the client.
	 */
	private List<InternetAddress> contacts = null;


	/**
	 * The client application type.
	 */
	private ApplicationType applicationType = null;


	/**
	 * The client name.
	 */
	private String name = null;


	/**
	 * The client application logo.
	 */
	private URL logoURL = null;


	/**
	 * The client policy for use of end-user data.
	 */
	private URL policyURL = null;


	/**
	 * The client terms of service.
	 */
	private URL termsOfServiceURL = null;


	/**
	 * The subject identifier type for responses to this client.
	 */
	private SubjectType subjectType = null;


	/**
	 * Sector identifier HTTPS URL.
	 */
	private URL sectorIDURL = null;


	/**
	 * Token endpoint authentication method.
	 */
	private ClientAuthenticationMethod tokenEndpointAuthMethod = null;


	/**
	 * URL for the client's JSON Web Key (JWK) set containing key(s) that
	 * are used in signing Token endpoint requests and OpenID request 
	 * objects. If {@link #encryptionJWKURL} is not provided, also used to 
	 * encrypt the ID Token and UserInfo endpoint responses to the client.
	 */
	private URL jwkSetURL = null;


	/**
	 * URL for the client's JSON Web Key (JWK) set containing key(s) that
	 * are used to encrypt the ID Token and UserInfo endpoint responses to 
	 * the client.
	 */
	private URL encryptionJWKSetURL = null;


	/**
	 * URL for the client's PEM encoded X.509 certificate or certificate 
	 * chain that is used for signing Token endpoint requests and OpenID
	 * request objects. If {@link #encryptionX509URL} is not provided, also
	 * used to encrypt the ID Token and UserInfo endpoint responses to the
	 * client.
	 */
	private URL x509URL = null;


	/**
	 * URL for the client's PEM encoded X.509 certificate or certificate
	 * chain that is used to encrypt the ID Token and UserInfo endpoint
	 * responses to the client.
	 */
	private URL encryptionX509URL = null;


	/**
	 * The JSON Web Signature (JWS) algorithm required for the OpenID 
	 * request objects sent by this client.
	 */
	private JWSAlgorithm requestObjectJWSAlg = null;


	/**
	 * The JSON Web Signature (JWS) algorithm required for the ID Tokens
	 * issued to this client.
	 */
	private JWSAlgorithm idTokenJWSAlg = null;


	/**
	 * The JSON Web Encryption (JWE) algorithm required for the ID Tokens
	 * issued to this client.
	 */
	private JWEAlgorithm idTokenJWEAlg = null;


	/**
	 * The encryption method (JWE enc) required for the ID Tokens issued to
	 * this client.
	 */
	private EncryptionMethod idTokenJWEEnc = null;


	/**
	 * The JSON Web Signature (JWS) algorithm required for the UserInfo
	 * responses to this client.
	 */
	private JWSAlgorithm userInfoJWSAlg = null;


	/**
	 * The JSON Web Encryption (JWE) algorithm required for the UserInfo
	 * responses to this client.
	 */
	private JWEAlgorithm userInfoJWEAlg = null;


	/**
	 * The encryption method (JWE enc) required for the UserInfo responses
	 * to this client.
	 */
	private EncryptionMethod userInfoJWEEnc = null;


	/**
	 * The default max authentication age, in seconds. If not specified 0.
	 */
	private int defaultMaxAge = 0;


	/**
	 * If {@code true} the {@code auth_time} claim in the ID Token is
	 * required by default.
	 */
	private boolean requiresAuthTime = false;


	/**
	 * The default Authentication Context Class Reference (ACR).
	 */
	private ACR defaultACR = null;


	/**
	 * Authorisation server initiated login HTTPS URL.
	 */
	private URL initiateLoginURI = null;


	/**
	 * Logout redirect URL.
	 */
	private URL postLogoutRedirectURI = null;


	/** 
	 * Creates a new OpenID Connect client details instance.
	 *
	 * @param id The client ID. Must not be {@code null}.
	 */
	public Client(final ClientID id) {

		if (id == null)
			throw new IllegalArgumentException("The client ID must not be null");

		this.id = id;
	}


	/**
	 * Gets the client ID.
	 *
	 * @return The client ID.
	 */
	public ClientID getID() {

		return id;
	}
	
	
	/**
	 * Gets the redirect URIs for the client.
	 *
	 * @return The redirect URIs, {@code null} if none.
	 */
	public Set<URL> getRedirectURIs() {
	
		return redirectURIs;
	}
	
	
	/**
	 * Sets the redirect URIs for the client.
	 *
	 * @param redirectURIs The redirect URIs, {@code null} if none.
	 */
	public void setRedirectURIs(final Set<URL> redirectURIs) {
	
		this.redirectURIs = redirectURIs;
	}


	/**
	 * Gets the administrator contacts for the client.
	 *
	 * @return The administrator contacts, {@code null} if none.
	 */
	public List<InternetAddress> getContacts() {

		return contacts;
	}


	/**
	 * Sets the administrator contacts for the client.
	 *
	 * @param contacts The administrator contacts, {@code null} if none.
	 */
	public void setContacts(final List<InternetAddress> contacts) {

		this.contacts = contacts;
	}


	/**
	 * Gets the client application type.
	 *
	 * @return The client application type, {@code null} if not specified.
	 */
	public ApplicationType getApplicationType() {

		return applicationType;
	}


	/**
	 * Sets the client application type.
	 *
	 * @param applicationType The client application type, {@code null} if 
	 *                        not specified.
	 */
	public void setApplicationType(final ApplicationType applicationType) {

		this.applicationType = applicationType;
	}


	/**
	 * Gets the client name.
	 *
	 * @return The client name, {@code null} if not specified.
	 */
	public String getName() {

		return name;
	}


	/**
	 * Sets the client name.
	 *
	 * @param name The client name, {@code null} if not specified.
	 */
	public void setName(final String name) {

		this.name = name;
	}


	/**
	 * Gets the client application logo.
	 *
	 * @return The logo URL, {@code null} if not specified.
	 */
	public URL getLogoURL() {

		return logoURL;
	}


	/**
	 * Sets the client application logo.
	 *
	 * @param logoURL The logo URL, {@code null} if not specified.
	 */
	public void setLogoURL(final URL logoURL) {

		this.logoURL = logoURL;
	}


	/**
	 * Gets the client policy for use of end-user data.
	 *
	 * @return The policy URL, {@code null} if not specified.
	 */
	public URL getPolicyURL() {

		return policyURL;
	}


	/**
	 * Sets the client policy for use of end-user data.
	 *
	 * @param policyURL The policy URL, {@code null} if not specified.
	 */
	public void setPolicyURL(final URL policyURL) {

		this.policyURL = policyURL;
	}


	/**
	 * Gets the client terms of service.
	 *
	 * @return The terms of service URL, {@code null} if not specified.
	 */
	public URL getTermsOfServiceURL() {

		return termsOfServiceURL;
	}


	/**
	 * Sets the client terms of service.
	 *
	 * @param termsOfServiceURL The terms of service URL, {@code null} if
	 *                          not specified.
	 */
	public void setTermsOfServiceURL(final URL termsOfServiceURL) {

		this.termsOfServiceURL = termsOfServiceURL;
	}


	/**
	 * Gets the subject identifier type for responses to this client.
	 *
	 * @return The subject identifier type, {@code null} if not specified.
	 */
	public SubjectType getSubjectType() {

		return subjectType;
	}


	/**
	 * Sets the subject identifier type for responses to this client.
	 *
	 * @param subjectType The subject identifier type, {@code null} if not 
	 *                    specified.
	 */
	public void setSubjectType(final SubjectType subjectType) {

		this.subjectType = subjectType;
	}


	/**
	 * Gets the sector identifier URL.
	 *
	 * @return The sector identifier URL, {@code null} if not specified.
	 */
	public URL getSectorIDURL() {

		return sectorIDURL;
	}


	/**
	 * Sets the sector identifier URL.
	 *
	 * @param sectorIDURL The sector identifier URL, {@code null} if not 
	 *                    specified.
	 */
	public void setSectorIDURL(final URL sectorIDURL) {

		this.sectorIDURL = sectorIDURL;
	}


	/**
	 * Gets the Token endpoint authentication method.
	 *
	 * @return The Token endpoint authentication method, {@code null} if 
	 *         not specified.
	 */
	public ClientAuthenticationMethod getTokenEndpointAuthMethod() {

		return tokenEndpointAuthMethod;
	}


	/**
	 * Sets the Token endpoint authentication method.
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
	 * the client.
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
	 * the client.
	 *
	 * @param jwkSetURL The JWK set URL, {@code null} if not specified.
	 */
	public void setJWKSetURL(final URL jwkSetURL) {

		this.jwkSetURL = jwkSetURL;
	}


	/**
	 * Gets the URL for the client's JSON Web Key (JWK) set containing
	 * key(s) that ares used to encrypt the ID Token and UserInfo endpoint 
	 * responses to the client.
	 *
	 * @return The encryption JWK set URL, {@code null} if not specified.
	 */
	public URL getEncryptionJWKSetURL() {

		return encryptionJWKSetURL;
	}


	/**
	 * Sets the URL for the client's JSON Web Key (JWK) set containing
	 * key(s) that are used to encrypt the ID Token and UserInfo endpoint 
	 * responses to the client.
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
	 * responses to the client.
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
	 * responses to the client.
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
	 * endpoint responses to the client.
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
	 * endpoint responses to the client.
	 *
	 * @param encryptionX509URL The encryption X.509 certificate URL, 
	 *                          {@code null} if not specified.
	 */
	public void setEncryptionX509URL(final URL encryptionX509URL) {

		this.encryptionX509URL = encryptionX509URL;
	}


	/**
	 * Gets the JSON Web Signature (JWS) algorithm required for the OpenID 
	 * request objects sent by this client.
	 *
	 * @return The JWS algorithm, {@code null} if not specified.
	 */
	public JWSAlgorithm getRequestObjectJWSAlgorithm() {

		return requestObjectJWSAlg;
	}


	/**
	 * Sets the JSON Web Signature (JWS) algorithm required for the OpenID 
	 * request objects sent by this client.
	 *
	 * @param requestObjectJWSAlg The JWS algorithm, {@code null} if not 
	 *                            specified.
	 */
	public void setRequestObjectJWSAlgorithm(final JWSAlgorithm requestObjectJWSAlg) {

		this.requestObjectJWSAlg = requestObjectJWSAlg;
	}


	/**
	 * Gets the JSON Web Signature (JWS) algorithm required for the ID 
	 * Tokens issued to this client.
	 *
	 * @return The JWS algorithm, {@code null} if not specified.
	 */
	public JWSAlgorithm getIDTokenJWSAlgorithm() {

		return idTokenJWSAlg;
	}


	/**
	 * Sets the JSON Web Signature (JWS) algorithm required for the ID 
	 * Tokens issued to this client.
	 *
	 * @param idTokenJWSAlg The JWS algorithm, {@code null} if not 
	 *                      specified.
	 */
	public void setIDTokenJWSAlgorithm(final JWSAlgorithm idTokenJWSAlg) {

		this.idTokenJWSAlg = idTokenJWSAlg;
	}


	/**
	 * Gets the JSON Web Encryption (JWE) algorithm required for the ID 
	 * Tokens issued to this client.
	 *
	 * @return The JWE algorithm, {@code null} if not specified.
	 */
	public JWEAlgorithm getIDTokenJWEAlgorithm() {

		return idTokenJWEAlg;
	}


	/**
	 * Sets the JSON Web Encryption (JWE) algorithm required for the ID 
	 * Tokens issued to this client.
	 *
	 * @param idTokenJWEAlg The JWE algorithm, {@code null} if not 
	 *                      specified.
	 */
	public void setIDTokenJWEAlgorithm(final JWEAlgorithm idTokenJWEAlg) {

		this.idTokenJWEAlg = idTokenJWEAlg;
	}


	/**
	 * Gets the encryption method (JWE enc) required for the ID Tokens 
	 * issued to this client.
	 *
	 * @return The JWE encryption method, {@code null} if not specified.
	 */
	public EncryptionMethod getIDTokenJWEEncryptionMethod() {

		return idTokenJWEEnc;
	}


	/**
	 * Sets the encryption method (JWE enc) required for the ID Tokens 
	 * issued to this client.
	 *
	 * @param idTokenJWEEnc The JWE encryption method, {@code null} if not 
	 *                      specified.
	 */
	public void setIDTokenJWEEncryptionMethod(final EncryptionMethod idTokenJWEEnc) {

		this.idTokenJWEEnc = idTokenJWEEnc;
	}


	/**
	 * Gets the JSON Web Signature (JWS) algorithm required for the 
	 * UserInfo responses to this client.
	 *
	 * @return The JWS algorithm, {@code null} if not specified.
	 */
	public JWSAlgorithm getUserInfoJWSAlgorithm() {

		return userInfoJWSAlg;
	}


	/**
	 * Sets the JSON Web Signature (JWS) algorithm required for the 
	 * UserInfo responses to this client.
	 *
	 * @param userInfoJWSAlg The JWS algorithm, {@code null} if not 
	 *                       specified.
	 */
	public void setUserInfoJWSAlgorithm(final JWSAlgorithm userInfoJWSAlg) {

		this.userInfoJWSAlg = userInfoJWSAlg;
	}


	/**
	 * Gets the JSON Web Encryption (JWE) algorithm required for the 
	 * UserInfo responses to this client.
	 *
	 * @return The JWE algorithm, {@code null} if not specified.
	 */
	public JWEAlgorithm getUserInfoJWEAlgorithm() {

		return userInfoJWEAlg;
	}


	/**
	 * Sets the JSON Web Encryption (JWE) algorithm required for the 
	 * UserInfo responses to this client.
	 *
	 * @param userInfoJWEAlg The JWE algorithm, {@code null} if not
	 *                       specified.
	 */
	public void setUserInfoJWEAlgorithm(final JWEAlgorithm userInfoJWEAlg) {

		this.userInfoJWEAlg = userInfoJWEAlg;
	}


	/**
	 * Gets the encryption method (JWE enc) required for the UserInfo 
	 * responses to this client.
	 *
	 * @return The JWE encryption method, {@code null} if not specified.
	 */
	public EncryptionMethod getUserInfoJWEEncryptionMethod() {

		return userInfoJWEEnc;
	}


	/**
	 * Sets the encryption method (JWE enc) required for the UserInfo 
	 * responses to this client.
	 *
	 * @param userInfoJWEEnc The JWE encryption method, {@code null} if not 
	 *                       specified.
	 */
	public void setUserInfoJWEEncryptionMethod(final EncryptionMethod userInfoJWEEnc) {

		this.userInfoJWEEnc = userInfoJWEEnc;
	}


	/**
	 * Gets the default maximum authentication age.
	 *
	 * @return The default max authentication age, in seconds. If not
	 *         specified 0.
	 */
	public int getDefaultMaxAge() {

		return defaultMaxAge;
	}


	/**
	 * Sets the default maximum authentication age.
	 *
	 * @param defaultMaxAge The default max authentication age, in seconds.
	 *                      If not specified 0.
	 */
	public void setDefaultMaxAge(final int defaultMaxAge) {

		this.defaultMaxAge = defaultMaxAge;
	}


	/**
	 * Gets the default requirement for the {@code auth_time} claim in the
	 * ID Token.
	 *
	 * @return If {@code true} the {@code auth_Time} claim in the ID Token 
	 *         is required by default.
	 */
	public boolean requiresAuthTime() {

		return requiresAuthTime;
	}


	/**
	 * Sets the default requirement for the {@code auth_time} claim in the
	 * ID Token.
	 *
	 * @param requireAuthTime If {@code true} the {@code auth_Time} claim 
	 *                        in the ID Token is required by default.
	 */
	public void requiresAuthTime(final boolean requireAuthTime) {

		this.requiresAuthTime = requiresAuthTime;
	}


	/**
	 * Gets the default Authentication Context Class Reference (ACR).
	 *
	 * @return The default ACR, {@code null} if not specified.
	 */
	public ACR getDefaultACR() {

		return defaultACR;
	}


	/**
	 * Sets the default Authentication Context Class Reference (ACR).
	 *
	 * @param defaultACR The default ACR, {@code null} if not specified.
	 */
	public void setDefaultACR(final ACR defaultACR) {

		this.defaultACR = defaultACR;
	}


	/**
	 * Gets the authorisation server initiated login HTTPS URL.
	 *
	 * @return The login URL, {@code null} if not specified.
	 */
	public URL getInitiateLoginURI() {

		return initiateLoginURI;
	}


	/**
	 * Sets the authorisation server initiated login HTTPS URL.
	 *
	 * @param initiateLoginURI The login URL, {@code null} if not 
	 *                         specified.
	 */
	public void setInitiateLoginURI(final URL initiateLoginURI) {

		this.initiateLoginURI = initiateLoginURI;
	}


	/**
	 * Gets the post logout redirect URL.
	 *
	 * @return The post logout redirect URL, {@code null} if not specified.
	 */
	public URL getPostLogoutRedirectURI() {

		return postLogoutRedirectURI;
	}


	/**
	 * Sets the post logout redirect URL.
	 *
	 * @param postLogoutRedirectURI The post logout redirect URL, 
	 *                              {@code null} if not specified.
	 */
	public void setPostLogoutRedirectURI(final URL postLogoutRedirectURI) {

		this.postLogoutRedirectURI = postLogoutRedirectURI;
	}
}

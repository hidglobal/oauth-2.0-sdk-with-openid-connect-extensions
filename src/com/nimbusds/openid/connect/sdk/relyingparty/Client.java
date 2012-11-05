package com.nimbusds.openid.connect.sdk.relyingparty;


import java.net.URL;

import java.util.HashSet;
import java.util.Set;

import javax.mail.internet.InternetAddress;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;

import com.nimbusds.openid.connect.sdk.claims.AuthenticationContextClassReference;
import com.nimbusds.openid.connect.sdk.claims.ClientID;
import com.nimbusds.openid.connect.sdk.claims.UserID;

import com.nimbusds.openid.connect.sdk.messages.ClientAuthenticationMethod;


/**
 * OpenID Connect client details.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-11-05)
 */
public class Client {


	/**
	 * The registered client ID.
	 */
	private ClientID clientID;


	/**
	 * Administrator contacts for the client.
	 */
	private InternetAddress[] contacts;


	/**
	 * The client application type.
	 */
	private ApplicationType applicationType;


	/**
	 * The client application name.
	 */
	private String applicationName;


	/**
	 * The client application logo URL.
	 */
	private URL applicationLogoURL;


	/**
	 * The client application policy for use of end-user data.
	 */
	private URL privacyPolicyURL;


	/**
	 * Redirect URIs.
	 */
	private Set<URL> redirectURIs;


	/**
	 * The user ID type for responses to this client.
	 */
	private UserID.Type userIDType;


	/**
	 * Sector identifier HTTPS URL.
	 */
	private URL sectorIDURL;


	/**
	 * Token endpoint authentication method.
	 */
	private ClientAuthenticationMethod tokenEndpointAuthMethod;


	/**
	 * URL for the client's JSON Web Key (JWK) that is used in signing 
	 * Token endpoint requests and OpenID request objects. If
	 * {@link #encryptionJWKURL} if not provided, also used to encrypt the
	 * ID Token and UserInfo endpoint responses to the client.
	 */
	private URL jwkURL;


	/**
	 * URL for the client's JSON Web Key (JWK) that is used to encrypt the
	 * ID Token and UserInfo endpoint responses to the client.
	 */
	private URL encryptionJWKURL;


	/**
	 * URL for the client's PEM encoded X.509 certificate or certificate 
	 * chain that is used for signing Token endpoint requests and OpenID
	 * request objects. If {@link #encryptionX509URL} is not provided, also
	 * used to encrypt the ID Token and UserInfo endpoint responses to the
	 * client.
	 */
	private URL x509URL;


	/**
	 * URL for the client's PEM encoded X.509 certificate or certificate
	 * chain that is used to encrypt the ID Token and UserInfo endpoint
	 * responses to the client.
	 */
	private URL encryptionX509URL;


	/**
	 * The JSON Web Signature (JWS) algorithm required for the OpenID 
	 * request objects sent by this client.
	 */
	private JWSAlgorithm requestObjectJWSAlg;


	/**
	 * The JSON Web Signature (JWS) algorithm required for the ID Tokens
	 * issued to this client.
	 */
	private JWSAlgorithm idTokenJWSAlg;


	/**
	 * The JSON Web Encryption (JWE) algorithm required for the ID Tokens
	 * issued to this client.
	 */
	private JWEAlgorithm idTokenJWEAlg;


	/**
	 * The encryption method (JWE enc) required for the ID Tokens issued to
	 * this client.
	 */
	private EncryptionMethod idTokenJWEEnc;


	/**
	 * The JSON Web Signature (JWS) algorithm required for the UserInfo
	 * responses to this client.
	 */
	private JWSAlgorithm userInfoJWSAlg;


	/**
	 * The JSON Web Encryption (JWE) algorithm required for the UserInfo
	 * responses to this client.
	 */
	private JWEAlgorithm userInfoJWEAlg;


	/**
	 * The encryption method (JWE enc) required for the UserInfo responses
	 * to this client.
	 */
	private EncryptionMethod userInfoJWEEnc;


	/**
	 * The default max authentication age, in seconds. If not specified -1.
	 */
	private int defaultMaxAge = -1;


	/**
	 * If {@code true} the {@code auth_time} claim in the ID Token is
	 * required by default.
	 */
	private boolean requireAuthTime = false;


	/**
	 * The default Authentication Context Class Reference (ACR).
	 */
	private AuthenticationContextClassReference defaultACR;


	/** 
	 * Creates a new OpenID Connect client details instance.
	 *
	 * @param clientID The client ID. Must not be {@code null}.
	 */
	public Client(final ClientID clientID) {

		if (clientID == null)
			throw new IllegalArgumentException("The client ID must not be null");

		this.clientID = clientID;
	}


	/**
	 * Gets the client ID.
	 *
	 * @return The client ID.
	 */
	public ClientID getClientID() {

		return clientID;
	}


	/**
	 * Gets the administrator contacts for the client.
	 *
	 * @return The administrator contacts for the client, {@code null} if
	 *         none.
	 */
	public InternetAddress[] getContacts() {

		return contacts;
	}


	/**
	 * Sets the administrator contacts for the client.
	 *
	 * @param contacts The administrator contacts for the client, 
	 *                 {@code null} if none.
	 */
	public void setContacts(final InternetAddress[] contacts) {

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
	 * Gets the client application name.
	 *
	 * @return The client application name, {@code null} if not specified.
	 */
	public String getApplicationName() {

		return applicationName;
	}


	/**
	 * Sets the client application name.
	 *
	 * @param applicationName The client application name, {@code null} if 
	 *                        not specified.
	 */
	public void setApplicationName(final String applicationName) {

		this.applicationName = applicationName;
	}


	/**
	 * Gets the client application logo URL.
	 *
	 * @return The client application logo URL, {@code null} if not
	 *         specified.
	 */
	public URL getApplicationLogoURL() {

		return applicationLogoURL;
	}


	/**
	 * Sets the client application logo URL.
	 *
	 * @param applicationLogoURL The client application logo URL, 
	 *                           {@code null} if not specified.
	 */
	public void setApplicationLogoURL(final URL applicationLogoURL) {

		this.applicationLogoURL = applicationLogoURL;
	}


	/**
	 * Gets the client application policy for use of end-user data.
	 *
	 * @return The privacy policy URL, {@code null} if not specified.
	 */
	public URL getPrivacyPolicyURL() {

		return privacyPolicyURL;
	}


	/**
	 * Sets the client application policy for use of end-user data.
	 *
	 * @param privacyPolicyURL The privacy policy URL, {@code null} if not 
	 *                         specified.
	 */
	public void setPrivacyPolicyURL(final URL privacyPolicyURL) {

		this.privacyPolicyURL = privacyPolicyURL;
	}


	/**
	 * Gets the user ID type for responses to this client.
	 *
	 * @return The user ID type, {@code null} if not specified.
	 */
	public UserID.Type getUserIDType() {

		return userIDType;
	}


	/**
	 * Sets the user ID type for responses to this client.
	 *
	 * @param userIDType The user ID type, {@code null} if not specified.
	 */
	public void setUserIDType(final UserID.Type userIDType) {

		this.userIDType = userIDType;
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
	 * Gets the URL for the client's JSON Web Key (JWK) that is used in 
	 * signing Token endpoint requests and OpenID request objects. If
	 * {@link #getEncryptionJWKURL} if not provided, also used to encrypt 
	 * the ID Token and UserInfo endpoint responses to the client.
	 *
	 * @return The JWK URL, {@code null} if not specified.
	 */
	public URL getJWKURL() {

		return jwkURL;
	}


	/**
	 * Sets the URL for the client's JSON Web Key (JWK) that is used in 
	 * signing Token endpoint requests and OpenID request objects. If
	 * {@link #getEncryptionJWKURL} if not provided, also used to encrypt 
	 * the ID Token and UserInfo endpoint responses to the client.
	 *
	 * @param jwkURL The JWK URL, {@code null} if not specified.
	 */
	public void setJWKURL(final URL jwkURL) {

		this.jwkURL = jwkURL;
	}


	/**
	 * Gets the URL for the client's JSON Web Key (JWK) that is used to 
	 * encrypt the ID Token and UserInfo endpoint responses to the client.
	 *
	 * @return The encryption JWK URL, {@code null} if not specified.
	 */
	public URL getEncryptionJWKURL() {

		return encryptionJWKURL;
	}


	/**
	 * Sets the URL for the client's JSON Web Key (JWK) that is used to 
	 * encrypt the ID Token and UserInfo endpoint responses to the client.
	 *
	 * @param encryptionJWKURL The encryption JWK URL, {@code null} if not 
	 *                         specified.
	 */
	public void setEncrytionJWKURL(final URL encryptionJWKURL) {

		this.encryptionJWKURL = encryptionJWKURL;
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
	 * Gets the default max authentication age.
	 *
	 * @return The default max authentication age, in seconds. If not
	 *         specified -1.
	 */
	public int getDefaultMaxAge() {

		return defaultMaxAge;
	}


	/**
	 * Sets the default max authentication age.
	 *
	 * @param defaultMaxAge The default max authentication age, in seconds.
	 *                      If not specified -1.
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

		return requireAuthTime;
	}


	/**
	 * Sets the default requirement for the {@code auth_time} claim in the
	 * ID Token.
	 *
	 * @param requireAuthTime If {@code true} the {@code auth_Time} claim 
	 *                        in the ID Token is required by default.
	 */
	public void requireAuthTime(final boolean requireAuthTime) {

		this.requireAuthTime = requireAuthTime;
	}


	/**
	 * Gets the default Authentication Context Class Reference (ACR).
	 *
	 * @return The default ACR, {@code null} if not specified.
	 */
	public AuthenticationContextClassReference getDefaultACR() {

		return defaultACR;
	}


	/**
	 * Sets the default Authentication Context Class Reference (ACR).
	 *
	 * @param defaultACR The default ACR, {@code null} if not specified.
	 */
	public void setDefaultACR(final AuthenticationContextClassReference defaultACR) {

		this.defaultACR = defaultACR;
	}

}
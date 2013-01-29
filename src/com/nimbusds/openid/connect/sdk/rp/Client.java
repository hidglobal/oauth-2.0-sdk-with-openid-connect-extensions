package com.nimbusds.openid.connect.sdk.rp;


import java.net.MalformedURLException;
import java.net.URL;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;

import com.nimbusds.oauth2.sdk.ParseException;

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;

import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;

import com.nimbusds.openid.connect.sdk.SubjectType;

import com.nimbusds.openid.connect.sdk.claims.ACR;


/**
 * OpenID Connect client details. Supports serialisation and parsing to / from
 * JSON object for the purpose of handling registration responses.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, section 2.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-29)
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
	private ApplicationType applicationType = ApplicationType.getDefault();


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
	private ClientAuthenticationMethod tokenEndpointAuthMethod = 
		ClientAuthenticationMethod.getDefault();


	/**
	 * URL for the client's JSON Web Key (JWK) set containing key(s) that
	 * are used in signing Token endpoint requests and OpenID request 
	 * objects. If {@link #encryptionJWKSetURL} is not provided, also used 
	 * to encrypt the ID Token and UserInfo endpoint responses to the 
	 * client.
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
	 * @return The client application type.
	 */
	public ApplicationType getApplicationType() {

		return applicationType;
	}


	/**
	 * Sets the client application type.
	 *
	 * @param applicationType The client application type, {@code null} for
	 *                        the default.
	 */
	public void setApplicationType(final ApplicationType applicationType) {

		if (applicationType == null)
			this.applicationType = ApplicationType.getDefault();
		else
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
	 * @return The Token endpoint authentication method.
	 */
	public ClientAuthenticationMethod getTokenEndpointAuthMethod() {

		return tokenEndpointAuthMethod;
	}


	/**
	 * Sets the Token endpoint authentication method.
	 *
	 * @param tokenEndpointAuthMethod The Token endpoint authentication 
	 *                                method, {@code null} for the default.
	 */
	public void setTokenEndpointAuthMethod(final ClientAuthenticationMethod tokenEndpointAuthMethod) {

		if (tokenEndpointAuthMethod == null)
			this.tokenEndpointAuthMethod = ClientAuthenticationMethod.getDefault();
		else
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


	/**
	 * Returns the client properties as a JSON object.
	 *
	 * @return The client properties as a JSON object.
	 */
	public JSONObject toJSONObject() {

		JSONObject o = new JSONObject();

		o.put("client_id", id.getValue());

		if (redirectURIs != null) {

			StringBuilder sb = new StringBuilder();

			for (URL uri: redirectURIs) {

				if (sb.length() > 0)
					sb.append(' ');

				sb.append(uri.toString());
			}

			o.put("redirect_uris", sb.toString());
		}


		if (contacts != null) {

			StringBuilder sb = new StringBuilder();

			for (InternetAddress email: contacts) {

				if (sb.length() > 0)
					sb.append(' ');

				sb.append(email.getAddress());
			}

			o.put("contacts", sb.toString());
		}


		o.put("application_type", applicationType.toString());


		if (name != null)
			o.put("client_name", name);


		if (logoURL != null)
			o.put("logo_url", logoURL.toString());


		if (policyURL != null)
			o.put("policy_url", policyURL.toString());


		if (termsOfServiceURL != null)
			o.put("tos_url", termsOfServiceURL.toString());


		if (subjectType != null)
			o.put("subject_type", subjectType.toString());


		if (sectorIDURL != null)
			o.put("sector_identifier_url", sectorIDURL.toString());


		o.put("token_endpoint_auth_method", tokenEndpointAuthMethod.toString());


		if (jwkSetURL != null)
			o.put("jwk_url", jwkSetURL.toString());


		if (encryptionJWKSetURL != null)
			o.put("jwk_encryption_url", encryptionJWKSetURL.toString());


		if (x509URL != null)
			o.put("x509_url", x509URL.toString());


		if (encryptionX509URL != null)
			o.put("x509_encryption_url", encryptionX509URL.toString());


		if (requestObjectJWSAlg != null)
			o.put("request_object_signing_alg", requestObjectJWSAlg.getName());


		if (idTokenJWSAlg != null)
			o.put("id_token_signed_response_alg", idTokenJWSAlg.getName());


		if (idTokenJWEAlg != null)
			o.put("id_token_encrypted_response_alg", idTokenJWEAlg.getName());


		if (idTokenJWEEnc != null)
			o.put("id_token_encrypted_response_enc", idTokenJWEEnc.getName());


		if (userInfoJWSAlg != null)
			o.put("userinfo_signed_response_alg", userInfoJWSAlg.getName());


		if (userInfoJWEAlg != null)
			o.put("userinfo_encrypted_response_alg", userInfoJWEAlg.getName());


		if (userInfoJWEEnc != null)
			o.put("userinfo_encrypted_response_enc", userInfoJWEEnc.getName());


		if (defaultMaxAge > 0)
			o.put("default_max_age", defaultMaxAge);


		o.put("require_auth_time", requiresAuthTime);


		if (defaultACR != null)
			o.put("default_acr", defaultACR.getValue());


		if (initiateLoginURI != null)
			o.put("initiate_login_uri", initiateLoginURI.toString());


		if (postLogoutRedirectURI != null)
			o.put("post_logout_redirect_url", postLogoutRedirectURI.toString());

		return o;
	}


	/**
	 * Parses an OpenID Connect client details instance from the specified
	 * JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The OpenID Connect client details.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an
	 *                        OpenID Connect client details instance.
	 */
	public static Client parse(final JSONObject jsonObject)
		throws ParseException {

		ClientID id = new ClientID(JSONObjectUtils.getString(jsonObject, "client_id"));

		Client client = new Client(id);

		if (jsonObject.containsKey("redirect_uris")) {

			Set<URL> redirectURIs = new HashSet<URL>();

			for (String uriString: JSONObjectUtils.getString(jsonObject, "redirect_uris").split(" ")) {

				try {
					redirectURIs.add(new URL(uriString));

				} catch (MalformedURLException e) {

					throw new ParseException("Invalid \"redirect_uris\" parameter: " +
						                  e.getMessage());
				}
			}

			client.setRedirectURIs(redirectURIs);
		}


		if (jsonObject.containsKey("contacts")) {

			List<InternetAddress> emailList = new LinkedList<InternetAddress>();

			for (String emailString: JSONObjectUtils.getString(jsonObject, "contacts").split(" ")) {

				try {
					emailList.add(new InternetAddress(emailString));

				} catch (AddressException e) {

					throw new ParseException("Invalid \"contacts\" parameter: " +
							         e.getMessage());
				}
			}

			client.setContacts(emailList);
		}


		if (jsonObject.containsKey("application_type"))
			client.setApplicationType(JSONObjectUtils.getEnum(jsonObject, 
				                                          "application_type", 
				                                          ApplicationType.class));


		if (jsonObject.containsKey("client_name"))
			client.setName(JSONObjectUtils.getString(jsonObject, "client_name"));


		if (jsonObject.containsKey("logo_url"))
			client.setLogoURL(JSONObjectUtils.getURL(jsonObject, "logo_url"));


		if (jsonObject.containsKey("policy_url"))
			client.setPolicyURL(JSONObjectUtils.getURL(jsonObject, "policy_url"));


		if (jsonObject.containsKey("tos_url"))
			client.setTermsOfServiceURL(JSONObjectUtils.getURL(jsonObject, "tos_url"));


		if (jsonObject.containsKey("subject_type"))
			client.setSubjectType(JSONObjectUtils.getEnum(jsonObject, "subject_type", SubjectType.class));


		if (jsonObject.containsKey("sector_identifier_url"))
			client.setSectorIDURL(JSONObjectUtils.getURL(jsonObject, "sector_identifier_url"));


		if (jsonObject.containsKey("token_endpoint_auth_method"))
			client.setTokenEndpointAuthMethod(new ClientAuthenticationMethod(
				JSONObjectUtils.getString(jsonObject, "token_endpoint_auth_method")));


		if (jsonObject.containsKey("jwk_url"))
			client.setJWKSetURL(JSONObjectUtils.getURL(jsonObject, "jwk_url"));


		if (jsonObject.containsKey("jwk_encryption_url"))
			client.setEncrytionJWKSetURL(JSONObjectUtils.getURL(jsonObject, "jwk_encryption_url"));


		if (jsonObject.containsKey("x509_url"))
			client.setX509URL(JSONObjectUtils.getURL(jsonObject, "x509_url"));


		if (jsonObject.containsKey("x509_encryption_url"))
			client.setEncryptionX509URL(JSONObjectUtils.getURL(jsonObject, "x509_encryption_url"));


		if (jsonObject.containsKey("request_object_signing_alg"))
			client.setRequestObjectJWSAlgorithm(new JWSAlgorithm(
				JSONObjectUtils.getString(jsonObject, "request_object_signing_alg")));


		if (jsonObject.containsKey("id_token_signed_response_alg"))
			client.setIDTokenJWSAlgorithm(new JWSAlgorithm(
				JSONObjectUtils.getString(jsonObject, "id_token_signed_response_alg")));


		if (jsonObject.containsKey("id_token_encrypted_response_alg"))
			client.setIDTokenJWEAlgorithm(new JWEAlgorithm(
				JSONObjectUtils.getString(jsonObject, "id_token_encrypted_response_alg")));


		if (jsonObject.containsKey("id_token_encrypted_response_enc"))
			client.setIDTokenJWEEncryptionMethod(new EncryptionMethod(
				JSONObjectUtils.getString(jsonObject, "id_token_encrypted_response_enc")));


		if (jsonObject.containsKey("userinfo_signed_response_alg"))
			client.setUserInfoJWSAlgorithm(new JWSAlgorithm(
				JSONObjectUtils.getString(jsonObject, "userinfo_signed_response_alg")));


		if (jsonObject.containsKey("userinfo_encrypted_response_alg"))
			client.setUserInfoJWEAlgorithm(new JWEAlgorithm(
				JSONObjectUtils.getString(jsonObject, "userinfo_encrypted_response_alg")));


		if (jsonObject.containsKey("userinfo_encrypted_response_enc"))
			client.setUserInfoJWEEncryptionMethod(new EncryptionMethod(
				JSONObjectUtils.getString(jsonObject, "userinfo_encrypted_response_enc")));


		if (jsonObject.containsKey("default_max_age"))
			client.setDefaultMaxAge(JSONObjectUtils.getInt(jsonObject, "default_max_age"));


		if (jsonObject.containsKey("require_auth_time"))
			client.requiresAuthTime(JSONObjectUtils.getBoolean(jsonObject, "require_auth_time"));


		if (jsonObject.containsKey("default_acr"))
			client.setDefaultACR(new ACR(JSONObjectUtils.getString(jsonObject, "default_acr")));


		if (jsonObject.containsKey("initiate_login_uri"))
			client.setInitiateLoginURI(JSONObjectUtils.getURL(jsonObject, "initiate_login_uri"));


		if (jsonObject.containsKey("post_logout_redirect_url"))
			client.setPostLogoutRedirectURI(JSONObjectUtils.getURL(jsonObject, "post_logout_redirect_url"));

		return client;
	}
}

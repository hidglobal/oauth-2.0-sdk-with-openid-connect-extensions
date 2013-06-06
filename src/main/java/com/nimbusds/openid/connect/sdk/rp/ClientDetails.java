package com.nimbusds.openid.connect.sdk.rp;


import java.net.MalformedURLException;
import java.net.URL;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagUtil;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;

import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;

import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.claims.ACR;



/**
 * OpenID Connect client details. Used in client registration requests and
 * responses.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic ClientDetails Registration 1.0, section 2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
public class ClientDetails {


	/**
	 * The registered client ID.
	 */
	private ClientID id;
	
	
	/**
	 * The client registration URI.
	 */
	private URL registrationURI;
	
	
	/**
	 * Redirect URIs.
	 */
	private Set<URL> redirectURIs;
	
	
	/**
	 * The expected OAuth 2.0 response types.
	 */
	private ResponseType responseTypes;
	
	
	/**
	 * The expected OAuth 2.0 grant types.
	 */
	private Set<GrantType> grantTypes;
	
	
	/**
	 * The client application type.
	 */
	private ApplicationType applicationType;


	/**
	 * Administrator contacts for the client.
	 */
	private List<InternetAddress> contacts;


	/**
	 * The client name.
	 */
	private Map<LangTag,String> nameEntries;


	/**
	 * The client application logo.
	 */
	private Map<LangTag,URL> logoURIEntries;


	/**
	 * The client policy for use of end-user data.
	 */
	private Map<LangTag,URL> policyURIEntries;


	/**
	 * The client terms of service.
	 */
	private Map<LangTag,URL> tosURIEntries;


	/**
	 * The subject identifier type for responses to this client.
	 */
	private SubjectType subjectType;


	/**
	 * Sector identifier URI.
	 */
	private URL sectorIDURI;


	/**
	 * Token endpoint authentication method.
	 */
	private ClientAuthenticationMethod authMethod;


	/**
	 * URI for this client's JSON Web Key (JWK) set containing key(s) that
	 * are used in signing requests to the server and key(s) for encrypting
	 * responses.
	 */
	private URL jwkSetURI;
	
	
	/**
	 * Pre-registered OpenID Connect request URIs.
	 */
	private Set<URL> requestObjectURIs;


	/**
	 * The JSON Web Signature (JWS) algorithm required for the OpenID 
	 * Connect request objects sent by this client.
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
	 * The default max authentication age, in seconds. If not specified 0.
	 */
	private int defaultMaxAge;


	/**
	 * If {@code true} the {@code auth_time} claim in the ID Token is
	 * required by default.
	 */
	private boolean requiresAuthTime;


	/**
	 * The default Authentication Context Class Reference (ACR) values.
	 */
	private Set<ACR> defaultACRs;


	/**
	 * Authorisation server initiated login HTTPS URL.
	 */
	private URL initiateLoginURI;


	/**
	 * Logout redirect URL.
	 */
	private URL postLogoutRedirectURI;


	/**
	 * The registration access token.
	 */
	private BearerAccessToken accessToken;


	/**
	 * The client secret.
	 */
	private Secret secret;


	/** 
	 * Creates a new OpenID Connect client details instance.
	 */
	public ClientDetails() {

		nameEntries = new HashMap<LangTag,String>();
		logoURIEntries = new HashMap<LangTag,URL>();
		policyURIEntries = new HashMap<LangTag,URL>();
		policyURIEntries = new HashMap<LangTag,URL>();
		tosURIEntries = new HashMap<LangTag,URL>();
	}


	/**
	 * Gets the registered client ID.
	 *
	 * @return The client ID, {@code null} if not specified.
	 */
	public ClientID getID() {

		return id;
	}


	/**
	 * Sets the registered client ID.
	 *
	 * @param id The client ID, {@code null} if not specified.
	 */
	public void setID(final ClientID id) {

		this.id = id;
	}
	
	
	/**
	 * Gets the URI of the client registration. Corresponds to the
	 * {@code registration_client_uri} client registration parameter.
	 * 
	 * @return The registration URI, {@code null} if not specified.
	 */
	public URL getRegistrationURI() {
		
		return registrationURI;
	}
	
	
	/**
	 * Sets the URI of the client registration. Corresponds to the
	 * {@code registration_client_uri} client registration parameter.
	 * 
	 * @param registrationURI The registration URI, {@code null} if not
	 *                        specified.
	 */
	public void setRegistrationURI(final URL registrationURI) {
		
		this.registrationURI = registrationURI;
	}
	
	
	/**
	 * Gets the redirect URIs for this client. Corresponds to the
	 * {@code redirect_uris} client registration parameter.
	 *
	 * @return The redirect URIs, {@code null} if not specified.
	 */
	public Set<URL> getRedirectURIs() {
	
		return redirectURIs;
	}
	
	
	/**
	 * Sets the redirect URIs for this client. Corresponds to the
	 * {@code redirect_uris} client registration parameter.
	 *
	 * @param redirectURIs The redirect URIs, {@code null} if not 
	 *                     specified.
	 */
	public void setRedirectURIs(final Set<URL> redirectURIs) {
	
		this.redirectURIs = redirectURIs;
	}
	
	
	/**
	 * Gets the expected OAuth 2.0 response types. Corresponds to the
	 * {@code response_types} client registration parameter.
	 * 
	 * @return The response types, {@code null} if not specified.
	 */
	public ResponseType getResponseTypes() {
		
		return responseTypes;
	}
	
	
	/**
	 * Sets the expected OAuth 2.0 response types. Corresponds to the
	 * {@code response_types} client registration parameter.
	 * 
	 * @param responseTypes The response types, {@code null} if not 
	 *                      specified.
	 */
	public void setResponseTypes(final ResponseType responseTypes) {
		
		this.responseTypes = responseTypes;
	}
	
	
	/**
	 * Gets the expected OAuth 2.0 grant types. Corresponds to the
	 * {@code grant_types} client registration parameter.
	 * 
	 * @return The grant types, {@code null} if not specified.
	 */
	public Set<GrantType> getGrantTypes() {
		
		return grantTypes;
	}
	
	
	/**
	 * Sets the expected OAuth 2.0 grant types. Corresponds to the
	 * {@code grant_types} client registration parameter.
	 * 
	 * @param grantTypes The grant types, {@code null} if not specified.
	 */
	public void setGrantTypes(final Set<GrantType> grantTypes) {
		
		this.grantTypes = grantTypes;
	}
	
	
	/**
	 * Gets the client application type. Corresponds to the
	 * {@code application_type} client registration parameter.
	 *
	 * @return The client application type, {@code null} if not specified.
	 */
	public ApplicationType getApplicationType() {

		return applicationType;
	}


	/**
	 * Sets the client application type. Corresponds to the
	 * {@code application_type} client registration parameter.
	 *
	 * @param applicationType The client application type, {@code null} if
	 *                        not specified.
	 */
	public void setApplicationType(final ApplicationType applicationType) {

		this.applicationType = applicationType;
	}


	/**
	 * Gets the administrator contacts for the client. Corresponds to the
	 * {@code contacts} client registration parameter.
	 *
	 * @return The administrator contacts, {@code null} if not specified.
	 */
	public List<InternetAddress> getContacts() {

		return contacts;
	}


	/**
	 * Sets the administrator contacts for the client. Corresponds to the
	 * {@code contacts} client registration parameter.
	 *
	 * @param contacts The administrator contacts, {@code null} if not
	 *                 specified.
	 */
	public void setContacts(final List<InternetAddress> contacts) {

		this.contacts = contacts;
	}


	/**
	 * Gets the client name. Corresponds to the {@code client_name} client 
	 * registration parameter, with no language tag.
	 *
	 * @return The client name, {@code null} if not specified.
	 */
	public String getName() {

		return getName(null);
	}


	/**
	 * Gets the client name. Corresponds to the {@code client_name} client
	 * registration parameter, with an optional language tag.
	 *
	 * @param langTag The language tag of the entry, {@code null} to get 
	 *                the non-tagged entry.
	 *
	 * @return The client name, {@code null} if not specified.
	 */
	public String getName(final LangTag langTag) {

		return nameEntries.get(langTag);
	}


	/**
	 * Gets the client name entries. Corresponds to the {@code client_name}
	 * client registration parameter.
	 *
	 * @return The client name entries, empty map if none.
	 */
	public Map<LangTag,String> getNameEntries() {

		return nameEntries;
	}


	/**
	 * Sets the client name. Corresponds to the {@code client_name} client
	 * registration parameter, with no language tag.
	 *
	 * @param name The client name, {@code null} if not specified.
	 */
	public void setName(final String name) {

		nameEntries.put(null, name);
	}


	/**
	 * Sets the client name. Corresponds to the {@code client_name} client
	 * registration parameter, with an optional language tag.
	 *
	 * @param name    The client name. Must not be {@code null}.
	 * @param langTag The language tag, {@code null} if not specified.
	 */
	public void setName(final String name, final LangTag langTag) {

		nameEntries.put(langTag, name);
	}


	/**
	 * Gets the client application logo. Corresponds to the 
	 * {@code logo_uri} client registration parameter, with no language 
	 * tag.
	 *
	 * @return The logo URI, {@code null} if not specified.
	 */
	public URL getLogoURI() {

		return getLogoURI(null);
	}


	/**
	 * Gets the client application logo. Corresponds to the 
	 * {@code logo_uri} client registration parameter, with an optional
	 * language tag.
	 *
	 * @return The logo URI, {@code null} if not specified.
	 */
	public URL getLogoURI(final LangTag langTag) {

		return logoURIEntries.get(langTag);
	}


	/**
	 * Gets the client application logo entries. Corresponds to the 
	 * {@code logo_uri} client registration parameter.
	 *
	 * @return The logo URI entries, empty map if none.
	 */
	public Map<LangTag,URL> getLogoURIEntries() {

		return logoURIEntries;
	}


	/**
	 * Sets the client application logo. Corresponds to the 
	 * {@code logo_uri} client registration parameter, with no language 
	 * tag.
	 *
	 * @param logoURI The logo URI, {@code null} if not specified.
	 */
	public void setLogoURI(final URL logoURI) {

		logoURIEntries.put(null, logoURI);
	}


	/**
	 * Sets the client application logo. Corresponds to the 
	 * {@code logo_uri} client registration parameter, with an optional
	 * language tag.
	 *
	 * @param logoURI The logo URI. Must not be {@code null}.
	 * @param langTag The language tag, {@code null} if not specified.
	 */
	public void setLogoURI(final URL logoURI, final LangTag langTag) {

		logoURIEntries.put(langTag, logoURI);
	}
	

	/**
	 * Gets the client policy for use of end-user data. Corresponds to the 
	 * {@code policy_uri} client registration parameter, with no language 
	 * tag.
	 *
	 * @return The policy URI, {@code null} if not specified.
	 */
	public URL getPolicyURI() {

		return getPolicyURI(null);
	}


	/**
	 * Gets the client policy for use of end-user data. Corresponds to the 
	 * {@code policy_url} client registration parameter, with an optional
	 * language tag.
	 *
	 * @return The policy URI, {@code null} if not specified.
	 */
	public URL getPolicyURI(final LangTag langTag) {

		return policyURIEntries.get(langTag);
	}


	/**
	 * Gets the client policy entries for use of end-user data. 
	 * Corresponds to the {@code policy_uri} client registration parameter.
	 *
	 * @return The policy URI entries, empty map if none.
	 */
	public Map<LangTag,URL> getPolicyURIEntries() {

		return policyURIEntries;
	}


	/**
	 * Sets the client policy for use of end-user data. Corresponds to the 
	 * {@code policy_uri} client registration parameter, with no language 
	 * tag.
	 *
	 * @param policyURI The policy URI, {@code null} if not specified.
	 */
	public void setPolicyURI(final URL policyURI) {

		policyURIEntries.put(null, policyURI);
	}


	/**
	 * Sets the client policy for use of end-user data. Corresponds to the 
	 * {@code policy_uri} client registration parameter, with an optional
	 * language tag.
	 *
	 * @param policyURI The policy URI. Must not be {@code null}.
	 * @param langTag   The language tag, {@code null} if not specified.
	 */
	public void setPolicyURI(final URL policyURI, final LangTag langTag) {

		policyURIEntries.put(langTag, policyURI);
	}


	/**
	 * Gets the client's terms of service. Corresponds to the 
	 * {@code tos_uri} client registration parameter, with no language 
	 * tag.
	 *
	 * @return The terms of service URI, {@code null} if not specified.
	 */
	public URL getTermsOfServiceURI() {

		return getTermsOfServiceURI(null);
	}


	/**
	 * Gets the client's terms of service. Corresponds to the 
	 * {@code tos_uri} client registration parameter, with an optional
	 * language tag.
	 *
	 * @return The terms of service URI, {@code null} if not specified.
	 */
	public URL getTermsOfServiceURI(final LangTag langTag) {

		return tosURIEntries.get(langTag);
	}


	/**
	 * Gets the client's terms of service entries. Corresponds to the 
	 * {@code tos_uri} client registration parameter.
	 *
	 * @return The terms of service URI entries, empty map if none.
	 */
	public Map<LangTag,URL> getTermsOfServiceURIEntries() {

		return tosURIEntries;
	}


	/**
	 * Sets the client's terms of service. Corresponds to the 
	 * {@code tos_uri} client registration parameter, with no language 
	 * tag.
	 *
	 * @param tosURI The terms of service URI, {@code null} if not 
	 *               specified.
	 */
	public void setTermsOfServiceURI(final URL tosURI) {

		tosURIEntries.put(null, tosURI);
	}


	/**
	 * Sets the client's terms of service. Corresponds to the 
	 * {@code tos_uri} client registration parameter, with an optional
	 * language tag.
	 *
	 * @param tosURI  The terms of service URI. Must not be {@code null}.
	 * @param langTag The language tag, {@code null} if not specified.
	 */
	public void setTermsOfServiceURI(final URL tosURI, final LangTag langTag) {

			tosURIEntries.put(langTag, tosURI);
	}


	/**
	 * Gets the subject identifier type for responses to this client. 
	 * Corresponds to the {@code subject_type} client registration 
	 * parameter.
	 *
	 * @return The subject identifier type, {@code null} if not specified.
	 */
	public SubjectType getSubjectType() {

		return subjectType;
	}


	/**
	 * Sets the subject identifier type for responses to this client. 
	 * Corresponds to the {@code subject_type} client registration 
	 * parameter.
	 *
	 * @param subjectType The subject identifier type, {@code null} if not 
	 *                    specified.
	 */
	public void setSubjectType(final SubjectType subjectType) {

		this.subjectType = subjectType;
	}


	/**
	 * Gets the sector identifier URI. Corresponds to the 
	 * {@code sector_identifier_uri} client registration parameter.
	 *
	 * @return The sector identifier URI, {@code null} if not specified.
	 */
	public URL getSectorIDURI() {

		return sectorIDURI;
	}


	/**
	 * Sets the sector identifier URI. Corresponds to the 
	 * {@code sector_identifier_uri} client registration parameter.
	 *
	 * @param sectorIDURI The sector identifier URI, {@code null} if not 
	 *                    specified.
	 */
	public void setSectorIDURI(final URL sectorIDURI) {

		this.sectorIDURI = sectorIDURI;
	}


	/**
	 * Gets the Token endpoint authentication method. Corresponds to the 
	 * {@code token_endpoint_auth_method} client registration parameter.
	 *
	 * @return The Token endpoint authentication method, {@code null} if
	 *         not specified.
	 */
	public ClientAuthenticationMethod getTokenEndpointAuthMethod() {

		return authMethod;
	}


	/**
	 * Sets the Token endpoint authentication method. Corresponds to the 
	 * {@code token_endpoint_auth_method} client registration parameter.
	 *
	 * @param authMethod The Token endpoint authentication  method, 
	 *                   {@code null} if not specified.
	 */
	public void setTokenEndpointAuthMethod(final ClientAuthenticationMethod authMethod) {

		this.authMethod = authMethod;
	}


	/**
	 * Gets the URI for this client's JSON Web Key (JWK) set containing 
	 * key(s) that are used in signing requests to the server and key(s) 
	 * for encrypting responses. Corresponds to the {@code jwks_uri} client 
	 * registration parameter.
	 *
	 * @return The JWK set URI, {@code null} if not specified.
	 */
	public URL getJWKSetURI() {

		return jwkSetURI;
	}


	/**
	 * Sets the URI for this client's JSON Web Key (JWK) set containing 
	 * key(s) that are used in signing requests to the server and key(s) 
	 * for encrypting responses. Corresponds to the {@code jwks_uri} client 
	 * registration parameter.
	 *
	 * @param jwkSetURI The JWK set URI, {@code null} if not specified.
	 */
	public void setJWKSetURL(final URL jwkSetURI) {

		this.jwkSetURI = jwkSetURI;
	}
	
	
	/**
	 * Gets the pre-registered OpenID Connect request object URIs. 
	 * Corresponds to the {@code request_uris} client registration 
	 * parameter.
	 * 
	 * @return The request object URIs, {@code null} if not specified.
	 */
	public Set<URL> getRequestObjectURIs() {
		
		return requestObjectURIs;
	}
	
	
	/**
	 * Sets the pre-registered OpenID Connect request object URIs. 
	 * Corresponds to the {@code request_uris} client registration 
	 * parameter.
	 * 
	 * @param requestObjectURIs The request object URIs, {@code null} if 
	 *                          not specified.
	 */
	public void setRequestObjectURIs(final Set<URL> requestObjectURIs) {
		
		this.requestObjectURIs = requestObjectURIs;
	}


	/**
	 * Gets the JSON Web Signature (JWS) algorithm required for the OpenID 
	 * Connect request objects sent by this client. Corresponds to the 
	 * {@code request_object_signing_alg} client registration parameter.
	 *
	 * @return The JWS algorithm, {@code null} if not specified.
	 */
	public JWSAlgorithm getRequestObjectJWSAlgorithm() {

		return requestObjectJWSAlg;
	}


	/**
	 * Sets the JSON Web Signature (JWS) algorithm required for the OpenID 
	 * Connect request objects sent by this client. Corresponds to the 
	 * {@code request_object_signing_alg} client registration parameter.
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
	 * {@code id_token_signed_response_alg} client registration parameter.
	 *
	 * @return The JWS algorithm, {@code null} if not specified.
	 */
	public JWSAlgorithm getIDTokenJWSAlgorithm() {

		return idTokenJWSAlg;
	}


	/**
	 * Sets the JSON Web Signature (JWS) algorithm required for the ID 
	 * Tokens issued to this client. Corresponds to the 
	 * {@code id_token_signed_response_alg} client registration parameter.
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
	 * {@code id_token_encrypted_response_alg} client registration 
	 * parameter.
	 *
	 * @return The JWE algorithm, {@code null} if not specified.
	 */
	public JWEAlgorithm getIDTokenJWEAlgorithm() {

		return idTokenJWEAlg;
	}


	/**
	 * Sets the JSON Web Encryption (JWE) algorithm required for the ID 
	 * Tokens issued to this client. Corresponds to the 
	 * {@code id_token_encrypted_response_alg} client registration 
	 * parameter.
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
	 * {@code id_token_encrypted_response_enc} client registration 
	 * parameter.
	 *
	 * @return The JWE encryption method, {@code null} if not specified.
	 */
	public EncryptionMethod getIDTokenJWEEncryptionMethod() {

		return idTokenJWEEnc;
	}


	/**
	 * Sets the encryption method (JWE enc) required for the ID Tokens 
	 * issued to this client. Corresponds to the 
	 * {@code id_token_encrypted_response_enc} client registration 
	 * parameter.
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
	 * {@code userinfo_signed_response_alg} client registration 
	 * parameter.
	 *
	 * @return The JWS algorithm, {@code null} if not specified.
	 */
	public JWSAlgorithm getUserInfoJWSAlgorithm() {

		return userInfoJWSAlg;
	}


	/**
	 * Sets the JSON Web Signature (JWS) algorithm required for the 
	 * UserInfo responses to this client. Corresponds to the 
	 * {@code userinfo_signed_response_alg} client registration 
	 * parameter.
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
	 * {@code userinfo_encrypted_response_alg} client registration 
	 * parameter.
	 *
	 * @return The JWE algorithm, {@code null} if not specified.
	 */
	public JWEAlgorithm getUserInfoJWEAlgorithm() {

		return userInfoJWEAlg;
	}


	/**
	 * Sets the JSON Web Encryption (JWE) algorithm required for the 
	 * UserInfo responses to this client. Corresponds to the 
	 * {@code userinfo_encrypted_response_alg} client registration 
	 * parameter.
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
	 * {@code userinfo_encrypted_response_enc} client registration 
	 * parameter.
	 *
	 * @return The JWE encryption method, {@code null} if not specified.
	 */
	public EncryptionMethod getUserInfoJWEEncryptionMethod() {

		return userInfoJWEEnc;
	}


	/**
	 * Sets the encryption method (JWE enc) required for the UserInfo 
	 * responses to this client. Corresponds to the 
	 * {@code userinfo_encrypted_response_enc} client registration 
	 * parameter.
	 *
	 * @param userInfoJWEEnc The JWE encryption method, {@code null} if not 
	 *                       specified.
	 */
	public void setUserInfoJWEEncryptionMethod(final EncryptionMethod userInfoJWEEnc) {

		this.userInfoJWEEnc = userInfoJWEEnc;
	}


	/**
	 * Gets the default maximum authentication age. Corresponds to the 
	 * {@code default_max_age} client registration parameter.
	 *
	 * @return The default max authentication age, in seconds. If not
	 *         specified 0.
	 */
	public int getDefaultMaxAge() {

		return defaultMaxAge;
	}


	/**
	 * Sets the default maximum authentication age. Corresponds to the 
	 * {@code default_max_age} client registration parameter.
	 *
	 * @param defaultMaxAge The default max authentication age, in seconds.
	 *                      If not specified 0.
	 */
	public void setDefaultMaxAge(final int defaultMaxAge) {

		this.defaultMaxAge = defaultMaxAge;
	}


	/**
	 * Gets the default requirement for the {@code auth_time} claim in the
	 * ID Token. Corresponds to the {@code require_auth_time} client 
	 * registration parameter.
	 *
	 * @return If {@code true} the {@code auth_Time} claim in the ID Token 
	 *         is required by default.
	 */
	public boolean requiresAuthTime() {

		return requiresAuthTime;
	}


	/**
	 * Sets the default requirement for the {@code auth_time} claim in the
	 * ID Token. Corresponds to the {@code require_auth_time} client 
	 * registration parameter.
	 *
	 * @param requiresAuthTime If {@code true} the {@code auth_Time} claim 
	 *                         in the ID Token is required by default.
	 */
	public void requiresAuthTime(final boolean requiresAuthTime) {

		this.requiresAuthTime = requiresAuthTime;
	}


	/**
	 * Gets the default Authentication Context Class Reference (ACR) 
	 * values. Corresponds to the {@code default_acr_values} client 
	 * registration parameter.
	 *
	 * @return The default ACR values, {@code null} if not specified.
	 */
	public Set<ACR> getDefaultACRs() {

		return defaultACRs;
	}


	/**
	 * Sets the default Authentication Context Class Reference (ACR)
	 * values. Corresponds to the {@code default_acr_values} client 
	 * registration parameter.
	 *
	 * @param defaultACRs The default ACRs, {@code null} if not specified.
	 */
	public void setDefaultACRs(final Set<ACR> defaultACRs) {

		this.defaultACRs = defaultACRs;
	}


	/**
	 * Gets the HTTPS URI that the authorisation server can call to
	 * initiate a login at the client. Corresponds to the 
	 * {@code initiate_login_uri} client registration parameter.
	 *
	 * @return The login URI, {@code null} if not specified.
	 */
	public URL getInitiateLoginURI() {

		return initiateLoginURI;
	}


	/**
	 * Sets the HTTPS URI that the authorisation server can call to
	 * initiate a login at the client. Corresponds to the 
	 * {@code initiate_login_uri} client registration parameter.
	 *
	 * @param loginURI The login URI, {@code null} if not specified.
	 */
	public void setInitiateLoginURI(final URL loginURI) {

		this.initiateLoginURI = loginURI;
	}


	/**
	 * Gets the post logout redirect URI. Corresponds to the 
	 * {@code post_logout_redirect_uri} client registration parameter.
	 *
	 * @return The logout URI, {@code null} if not specified.
	 */
	public URL getPostLogoutRedirectURI() {

		return postLogoutRedirectURI;
	}


	/**
	 * Sets the post logout redirect URI. Corresponds to the 
	 * {@code post_logout_redirect_uri} client registration parameter.
	 *
	 * @param logoutURI The logout URI, {@code null} if not specified.
	 */
	public void setPostLogoutRedirectURI(final URL logoutURI) {

		this.postLogoutRedirectURI = logoutURI;
	}


	/**
	 * Gets the registration access token. Corresponds to the 
	 * {@code registration_access_token} client registration parameter.
	 *
	 * @return The registration access token, {@code null} if not 
	 *         specified.
	 */
	public BearerAccessToken getRegistrationAccessToken() {

		return accessToken;
	}


	/**
	 * Sets the registration access token. Corresponds to the
	 * {@code registration_access_token} client registration parameter.
	 *
	 * @param accessToken The registration access token, {@code null} if 
	 *                    not specified.
	 */
	public void setRegistrationAccessToken(final BearerAccessToken accessToken) {

		this.accessToken = accessToken;
	}


	/**
	 * Gets the client secret. Corresponds to the {@code client_secret} and
	 * {@code client_secret_expires_at} client registration parameters.
	 *
	 * @return The client secret, {@code null} if not specified.
	 */
	public Secret getSecret() {

		return secret;
	}


	/**
	 * Sets the client secret. Corresponds to the {@code client_secret} and
	 * {@code client_secret_expires_at} client registration parameters.
	 *
	 * @param secret The client secret, {@code null} if not specified.
	 */
	public void setSecret(final Secret secret) {

		this.secret = secret;
	}
	
	
	/**
	 * Applies the client details defaults where no values have been
	 * specified.
	 */
	public void applyDefaults() {
		
		if (responseTypes == null) {
			responseTypes = ResponseType.getDefault();
		}
		
		if (grantTypes == null) {
			grantTypes = new HashSet<GrantType>();
			grantTypes.add(GrantType.AUTHORIZATION_CODE);
		}
		
		if (applicationType == null) {
			applicationType = ApplicationType.getDefault();
		}
		
		if (authMethod == null) {
			authMethod = ClientAuthenticationMethod.getDefault();
		}
		
		if (idTokenJWSAlg == null) {
			idTokenJWSAlg = JWSAlgorithm.RS256;
		}
	}


	/**
	 * Returns the client details as a JSON object. The key names match
	 * the corresponding client registration parameter names.
	 *
	 * @return The client details as a JSON object.
	 */
	public JSONObject toJSONObject() {

		JSONObject o = new JSONObject();

		if (id != null)
			o.put("client_id", id.getValue());

		if (redirectURIs != null) {

			JSONArray uriList = new JSONArray();

			for (URL uri: redirectURIs)
				uriList.add(uri.toString());

			o.put("redirect_uris", uriList);
		}
		
		
		if (registrationURI != null)
			o.put("registration_client_uri", registrationURI.toString());
		
		
		if (responseTypes != null) {
			
			JSONArray rtList = new JSONArray();
			
			for (ResponseType.Value rtValue: responseTypes)
				rtList.add(rtValue.toString());
			
			o.put("response_types", rtList);
		}
		
		
		if (grantTypes != null) {
			
			JSONArray grantList = new JSONArray();
			
			for (GrantType grant: grantTypes)
				grantList.add(grant.toString());
			
			o.put("grant_types", grantList);
		}
		
		
		if (applicationType != null)
			o.put("application_type", applicationType.toString());


		if (contacts != null) {

			JSONArray contactList = new JSONArray();

			for (InternetAddress email: contacts)
				contactList.add(email.toString());

			o.put("contacts", contactList);
		}


		if (! nameEntries.isEmpty()) {

			for (Map.Entry<LangTag,String> entry: nameEntries.entrySet()) {

				LangTag langTag = entry.getKey();
				String name = entry.getValue();
				
				if (name == null)
					continue;

				if (langTag == null)
					o.put("client_name", entry.getValue());
				else
					o.put("client_name#" + langTag, entry.getValue());
			} 
		}
		
		
		if (! logoURIEntries.isEmpty()) {

			for (Map.Entry<LangTag,URL> entry: logoURIEntries.entrySet()) {

				LangTag langTag = entry.getKey();
				URL uri = entry.getValue();
				
				if (uri == null)
					continue;

				if (langTag == null)
					o.put("logo_uri", entry.getValue());
				else
					o.put("logo_uri#" + langTag, entry.getValue().toString());
			} 
		}
		
		
		if (! policyURIEntries.isEmpty()) {

			for (Map.Entry<LangTag,URL> entry: policyURIEntries.entrySet()) {

				LangTag langTag = entry.getKey();
				URL uri = entry.getValue();
				
				if (uri == null)
					continue;

				if (langTag == null)
					o.put("policy_uri", entry.getValue());
				else
					o.put("policy_uri#" + langTag, entry.getValue().toString());
			} 
		}
		
		
		if (! tosURIEntries.isEmpty()) {

			for (Map.Entry<LangTag,URL> entry: tosURIEntries.entrySet()) {

				LangTag langTag = entry.getKey();
				URL uri = entry.getValue();
				
				if (uri == null)
					continue;

				if (langTag == null)
					o.put("tos_uri", entry.getValue());
				else
					o.put("tos_uri#" + langTag, entry.getValue().toString());
			} 
		}


		if (subjectType != null)
			o.put("subject_type", subjectType.toString());


		if (sectorIDURI != null)
			o.put("sector_identifier_uri", sectorIDURI.toString());


		if (authMethod != null)
			o.put("token_endpoint_auth_method", authMethod.toString());


		if (jwkSetURI != null)
			o.put("jwks_uri", jwkSetURI.toString());
		
		
		if (requestObjectURIs != null) {
			
			JSONArray uriList = new JSONArray();
			
			for (URL uri: requestObjectURIs)
				uriList.add(uri.toString());
			
			o.put("request_uris", uriList);
		}


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


		if (defaultACRs != null) {

			JSONArray acrList = new JSONArray();

			for (ACR acr: defaultACRs)
				acrList.add(acr);

			o.put("default_acr_values", acrList);
		}


		if (initiateLoginURI != null)
			o.put("initiate_login_uri", initiateLoginURI.toString());


		if (postLogoutRedirectURI != null)
			o.put("post_logout_redirect_uri", postLogoutRedirectURI.toString());


		// registration response parameters
		if (accessToken != null) {
			o.put("registration_access_token", accessToken.getValue());
		}

		if (secret != null) {
			o.put("client_secret", secret.getValue());

			if (secret.getExpirationDate() != null)
				o.put("client_secret_expires_at", secret.getExpirationDate().getTime());
		}

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
	public static ClientDetails parse(final JSONObject jsonObject)
		throws ParseException {

		ClientDetails client = new ClientDetails();

		if (jsonObject.containsKey("client_id"))
			client.setID(new ClientID(JSONObjectUtils.getString(jsonObject, "client_id")));
		
		
		if (jsonObject.containsKey("registration_client_uri"))
			client.setRegistrationURI(JSONObjectUtils.getURL(jsonObject, "registration_client_uri"));


		if (jsonObject.containsKey("redirect_uris")) {

			Set<URL> redirectURIs = new LinkedHashSet<URL>();

			for (String uriString: JSONObjectUtils.getStringArray(jsonObject, "redirect_uris")) {

				try {
					redirectURIs.add(new URL(uriString));

				} catch (MalformedURLException e) {

					throw new ParseException("Invalid \"redirect_uris\" parameter: " +
						                  e.getMessage());
				}
			}

			client.setRedirectURIs(redirectURIs);
		}
		
		
		if (jsonObject.containsKey("response_types")) {
			
			ResponseType responseTypes = new ResponseType();
			
			for (String responseTypeValue: JSONObjectUtils.getStringArray(jsonObject, "response_types")) {
				
				responseTypes.add(new ResponseType.Value(responseTypeValue));
			}
			
			client.setResponseTypes(responseTypes);
		}
		
		
		if (jsonObject.containsKey("grant_types")) {
			
			Set<GrantType> grantTypes = new LinkedHashSet<GrantType>();
			
			for (String grant: JSONObjectUtils.getStringArray(jsonObject, "grant_types")) {
				
				grantTypes.add(new GrantType(grant));
			}
			
			client.setGrantTypes(grantTypes);
		}
		
		
		if (jsonObject.containsKey("application_type"))
			client.setApplicationType(JSONObjectUtils.getEnum(jsonObject, 
				                                          "application_type", 
				                                          ApplicationType.class));
		
		

		if (jsonObject.containsKey("contacts")) {

			List<InternetAddress> emailList = new LinkedList<InternetAddress>();

			for (String emailString: JSONObjectUtils.getStringArray(jsonObject, "contacts")) {

				try {
					emailList.add(new InternetAddress(emailString));

				} catch (AddressException e) {

					throw new ParseException("Invalid \"contacts\" parameter: " +
							         e.getMessage());
				}
			}

			client.setContacts(emailList);
		}

		// Find lang-tagged client_name params
		Map<LangTag,Object> matches = LangTagUtil.find("client_name", jsonObject);

		for (Map.Entry<LangTag,Object> entry: matches.entrySet()) {

			try {
				client.setName((String)entry.getValue(), entry.getKey());

			} catch (ClassCastException e) {

				throw new ParseException("Invalid \"client_name\" (language tag) parameter");
			}
		}


		matches = LangTagUtil.find("logo_uri", jsonObject);

		for (Map.Entry<LangTag,Object> entry: matches.entrySet()) {

			try {
				client.setLogoURI(new URL((String)entry.getValue()), entry.getKey());

			} catch (Exception e) {

				throw new ParseException("Invalid \"logo_uri\" (language tag) parameter");
			}
		}
		
		
		matches = LangTagUtil.find("policy_uri", jsonObject);

		for (Map.Entry<LangTag,Object> entry: matches.entrySet()) {

			try {
				client.setPolicyURI(new URL((String)entry.getValue()), entry.getKey());

			} catch (Exception e) {

				throw new ParseException("Invalid \"policy_uri\" (language tag) parameter");
			}
		}
		
		
		matches = LangTagUtil.find("tos_uri", jsonObject);

		for (Map.Entry<LangTag,Object> entry: matches.entrySet()) {

			try {
				client.setTermsOfServiceURI(new URL((String)entry.getValue()), entry.getKey());

			} catch (Exception e) {

				throw new ParseException("Invalid \"tos_uri\" (language tag) parameter");
			}
		}


		if (jsonObject.containsKey("subject_type"))
			client.setSubjectType(JSONObjectUtils.getEnum(jsonObject, "subject_type", SubjectType.class));


		if (jsonObject.containsKey("sector_identifier_uri"))
			client.setSectorIDURI(JSONObjectUtils.getURL(jsonObject, "sector_identifier_uri"));


		if (jsonObject.containsKey("token_endpoint_auth_method"))
			client.setTokenEndpointAuthMethod(new ClientAuthenticationMethod(
				JSONObjectUtils.getString(jsonObject, "token_endpoint_auth_method")));

			
		if (jsonObject.containsKey("jwks_uri"))
			client.setJWKSetURL(JSONObjectUtils.getURL(jsonObject, "jwks_uri"));


		if (jsonObject.containsKey("request_uris")) {
			
			Set<URL> requestURIs = new LinkedHashSet<URL>();
			
			for (String uriString: JSONObjectUtils.getStringArray(jsonObject, "request_uris")) {
				
				try {
					requestURIs.add(new URL(uriString));
					
				} catch (MalformedURLException e) {
					
					throw new ParseException("Invalid \"request_uris\" parameter");
				}
			}
			
			client.setRequestObjectURIs(requestURIs);
		}
		
		
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


		if (jsonObject.containsKey("default_acr_values")) {

			Set<ACR> acrValues = new LinkedHashSet<ACR>();

			for (String acrString: JSONObjectUtils.getStringArray(jsonObject, "default_acr_values"))
				acrValues.add(new ACR(acrString));

			client.setDefaultACRs(acrValues);
		}


		if (jsonObject.containsKey("initiate_login_uri"))
			client.setInitiateLoginURI(JSONObjectUtils.getURL(jsonObject, "initiate_login_uri"));


		if (jsonObject.containsKey("post_logout_redirect_uri"))
			client.setPostLogoutRedirectURI(JSONObjectUtils.getURL(jsonObject, "post_logout_redirect_uri"));


		// Registration response parameters
		if (jsonObject.containsKey("registration_access_token"))
			client.setRegistrationAccessToken(new BearerAccessToken(
				JSONObjectUtils.getString(jsonObject, "registration_access_token")));


		if (jsonObject.containsKey("client_secret")) {

			String value = JSONObjectUtils.getString(jsonObject, "client_secret");

			Date exp = null;

			if (jsonObject.containsKey("client_secret_expires_at"))
				exp = new Date(JSONObjectUtils.getLong(jsonObject, "client_secret_expires_at"));

			client.setSecret(new Secret(value, exp));
		}

		return client;
	}
}

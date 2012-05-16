package com.nimbusds.openid.connect.messages;


import java.net.URL;

import com.nimbusds.openid.connect.claims.AuthenticationContextClassReference;
import com.nimbusds.openid.connect.claims.ClientID;
import com.nimbusds.openid.connect.claims.UserID;

import com.nimbusds.openid.connect.http.HTTPRequest;


/**
 * Client registration request.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-12)
 */
public class ClientRegistrationRequest implements Request {


	/**
	 * The registration type (always required).
	 */
	private ClientRegistrationType type;
	
	
	/**
	 * The client identifier for update requests.
	 */
	private ClientID clientID = null;
	
	
	/**
	 * The client secret to authenticate update requests.
	 */
	private String clientSecret = null;
	
	
	/** 
	 * An access token obtained out of band to authorise the registrant.
	 */
	private String accessToken = null;
	
	
	/**
	 * List of email addresses for people allowed to administer the 
	 * information for the client.
	 */
	private String contacts = null;
	
	
	/**
	 * The application type (optional).
	 */
	private ApplicationType applicationType = null;
	
	
	/**
	 * Name of the client to be presented to the user (optional).
	 */
	private String applicationName = null;
	
	
	/**
	 * The URL of a logo image for the client where it can be retrieved 
	 * (optional).
	 */
	private URL logoURL = null;
	
	
	/**
	 * List of redirect URIs. One of the URL must match the scheme, host, 
	 * and path segments of the {@code redirect_uri} in the authorization 
	 * request. Recommended for code flow; required for implicit flow.
	 */
	private URL[] redirectURIs = null;
	
	
	/**
	 * The requisted authentication type for the {@link TokenEndpoint}
	 * (optional).
	 */
	private ClientAuthentication tokenEndpointAuthType = null;
	
	
	/**
	 * A URL location that the relying party client provides to the 
	 * end-user to read about the how the profile data will be used 
	 * (optional).
	 */
	private URL policyURL = null;
	
	
	
	private URL jwtURL = null;
	
	
	
	private URL jwkEncryptionURL = null;
	
	
	
	private URL x509URL = null;
	
	
	
	private URL x509EncryptionURL = null;
	
	
	private URL sectorIdentifierURL = null;
	
	
	private UserID.Type userIDType = null;
	
	
	private String requireSignedRequestObject = null;
	
	
	private String[] userinfoSignedResponseAlgs = null;
	
	
	private String[] userinfoEncryptedResponseAlgs = null;
	
	
	private String[] idTokenSignedResponseAlgs = null;
	
	
	private String[] idTokenEncryptedResponseAlgs = null;
	
	
	private long defaultMaxAge = 0;
	
	
	private boolean requireAuthTime = false;
	
	
	private AuthenticationContextClassReference defaultACR = null;
	
	
	/**
	 * @inheritDoc
	 */
	public HTTPRequest toHTTPRequest() {
	
		return null;
	}

}

package com.nimbusds.openid.connect.sdk.rp;


import java.net.URL;
import java.util.Date;

import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.client.ClientInformation;
import com.nimbusds.oauth2.sdk.client.ClientMetadata;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;


/**
 * OpenID Connect client information. Encapsulates the registration and 
 * metadata details of an OpenID Connect client:
 * 
 * <ul>
 *     <li>The client identifier.
 *     <li>The client registration URI and access token.
 *     <li>The client OpenID Connect metadata.
 *     <li>The optional client secret for a confidential client.
 * </ul>
 * 
 * <p>This class is immutable.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol 
 *         (draft-ietf-oauth-dyn-reg-12), section 2, 3.2 and 5.1.
 *     <li>OpenID Connect Dynamic Client Registration 1.0.
 * </ul>
 * @author Vladimir Dzhuvinov
 */
public class OIDCClientInformation extends ClientInformation {

	
	/**
	 * Creates a new client information instance.
	 * 
	 * @param id              The client identifier. Must not be 
	 *                        {@code null}.
	 * @param registrationURI The client registration URI. Must not be
	 *                        {@code null}.
	 * @param accessToken     The client registration access token. Must
	 *                        not be {@code null}.
	 * @param metadata        The client metadata. Must not be 
	 *                        {@code null}.
	 * @param secret          The optional client secret, {@code null} if 
	 *                        not specified.
	 * @param issueDate       The issue date of the client identifier,
	 *                        {@code null} if not specified.
	 */
	public OIDCClientInformation(final ClientID id,
		                     final URL registrationURI,
				     final BearerAccessToken accessToken,
				     final ClientMetadata metadata,
				     final Secret secret,
				     final Date issueDate) {
		
		super(id, registrationURI, accessToken, metadata, secret, issueDate);
	}
	
	
	/**
	 * Gets the OpenID Connect client metadata.
	 * 
	 * @return The OpenID Connect client metadata.
	 */
	public OIDCClientMetadata getOIDCClientMetadata() {
		
		return (OIDCClientMetadata)getClientMetadata();
	}
}

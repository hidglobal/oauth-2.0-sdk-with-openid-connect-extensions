package com.nimbusds.openid.connect.sdk.rp;


import java.net.URL;
import java.util.Date;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.client.ClientInformation;
import com.nimbusds.oauth2.sdk.client.ClientMetadata;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


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
 *     <li>OpenID Connect Dynamic Client Registration 1.0.
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol 
 *         (draft-ietf-oauth-dyn-reg-12), section 2, 3.2 and 5.1.
 * </ul>
 * @author Vladimir Dzhuvinov
 */
@Immutable
public final class OIDCClientInformation extends ClientInformation {

	
	/**
	 * Creates a new OpenID Connect client information instance.
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
	
	
	/**
	 * Parses an OpenID Connect client information instance from the 
	 * specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The client information.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an
	 *                        OpenID Connect client information instance.
	 */
	public static OIDCClientInformation parse(final JSONObject jsonObject)
		throws ParseException {

		ClientID id = new ClientID(JSONObjectUtils.getString(jsonObject, "client_id"));
		
		
		URL registrationURI = JSONObjectUtils.getURL(jsonObject, "registration_client_uri");
		
		
		BearerAccessToken accessToken = new BearerAccessToken(
				JSONObjectUtils.getString(jsonObject, "registration_access_token"));

		
		OIDCClientMetadata metadata = OIDCClientMetadata.parse(jsonObject);
		
		
		Secret secret = null;
		
		if (jsonObject.containsKey("client_secret")) {

			String value = JSONObjectUtils.getString(jsonObject, "client_secret");

			Date exp = null;

			if (jsonObject.containsKey("client_secret_expires_at"))
				exp = new Date(JSONObjectUtils.getLong(jsonObject, "client_secret_expires_at") * 1000);

			secret = new Secret(value, exp);
		}
		
		
		Date issueDate = null;
		
		if (jsonObject.containsKey("client_id_issued_at")) {
			
			issueDate = new Date(JSONObjectUtils.getLong(jsonObject, "client_id_issued_at") * 1000);
		}

		
		return new OIDCClientInformation(id, registrationURI, accessToken, metadata, secret, issueDate);
	}
}

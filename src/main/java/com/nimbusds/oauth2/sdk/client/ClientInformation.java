package com.nimbusds.oauth2.sdk.client;


import java.net.URL;
import java.util.Date;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * Client information. Encapsulates the registration and metadata details of 
 * an OAuth 2.0 client:
 * 
 * <ul>
 *     <li>The client identifier.
 *     <li>The client registration URI and access token.
 *     <li>The client metadata.
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
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
@Immutable
public class ClientInformation {


	/**
	 * The registered client ID.
	 */
	private final ClientID id;
	
	
	/**
	 * The client registration URI.
	 */
	private final URL registrationURI;
	
	
	/**
	 * The client registration access token.
	 */
	private final BearerAccessToken accessToken;
	
	
	/**
	 * The client metadata.
	 */
	private final ClientMetadata metadata;


	/**
	 * The optional client secret.
	 */
	private final Secret secret;
	
	
	/**
	 * The date the client ID was issued at.
	 */
	private final Date issueDate;


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
	public ClientInformation(final ClientID id,
		                 final URL registrationURI,
				 final BearerAccessToken accessToken,
				 final ClientMetadata metadata,
				 final Secret secret,
				 final Date issueDate) {

		if (id == null)
			throw new IllegalArgumentException("The client identifier must not be null");
		
		this.id = id;
		
		
		if (registrationURI == null)
			throw new IllegalArgumentException("The client registration URI must not be null");
		
		this.registrationURI = registrationURI;
		
		
		if (accessToken == null)
			throw new IllegalArgumentException("The client registration access token must not be null");
		
		this.accessToken = accessToken;
		
		if (metadata == null)
			throw new IllegalArgumentException("The client metadata must not be null");
		
		this.metadata = metadata;
		
		this.secret = secret;
		
		this.issueDate = issueDate;
	}


	/**
	 * Gets the client ID. Corresponds to the {@code client_id} client
	 * registration parameter.
	 *
	 * @return The client ID, {@code null} if not specified.
	 */
	public ClientID getID() {

		return id;
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
	 * Gets the client metadata.
	 * 
	 * @return The client metadata.
	 */
	public ClientMetadata getClientMetadata() {
		
		return metadata;
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
	 * Gets the issue date of the client identifier. Corresponds to the
	 * {@code client_id_issued_at} client registration parameter.
	 * 
	 * @return The issue date, {@code null} if not specified.
	 */
	public Date getIssueDate() {
		
		return issueDate;
	}


	/**
	 * Returns the JSON object representation of this client information 
	 * instance.
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {

		JSONObject o = metadata.toJSONObject();

		o.put("client_id", id.value());
		
		o.put("registration_client_uri", registrationURI.toString());
		
		o.put("registration_access_token", accessToken.value());

		if (secret != null) {
			o.put("client_secret", secret.getValue());

			if (secret.getExpirationDate() != null)
				o.put("client_secret_expires_at", secret.getExpirationDate().getTime() / 1000);
		}
		
		if (issueDate != null) {
			
			o.put("client_id_issued_at", issueDate.getTime() / 1000);
		}

		return o;
	}


	/**
	 * Parses a client information instance from the specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The client information.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a
	 *                        client information instance.
	 */
	public static ClientInformation parse(final JSONObject jsonObject)
		throws ParseException {

		ClientID id = new ClientID(JSONObjectUtils.getString(jsonObject, "client_id"));
		
		
		URL registrationURI = JSONObjectUtils.getURL(jsonObject, "registration_client_uri");
		
		
		BearerAccessToken accessToken = new BearerAccessToken(
				JSONObjectUtils.getString(jsonObject, "registration_access_token"));

		
		ClientMetadata metadata = ClientMetadata.parse(jsonObject);
		
		
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

		
		return new ClientInformation(id, registrationURI, accessToken, metadata, secret, issueDate);
	}
}

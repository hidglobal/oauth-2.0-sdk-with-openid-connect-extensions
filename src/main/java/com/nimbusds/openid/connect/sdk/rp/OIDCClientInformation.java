package com.nimbusds.openid.connect.sdk.rp;


import java.net.URI;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.client.ClientInformation;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * OpenID Connect client information. Encapsulates the registration and 
 * metadata details of an OpenID Connect client:
 * 
 * <ul>
 *     <li>The client identifier.
 *     <li>The client OpenID Connect metadata.
 *     <li>The optional client secret for a confidential client.
 *     <li>The optional registration URI and access token if dynamic client
 *         registration is permitted.
 * </ul>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0.
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol
 *         (draft-ietf-oauth-dyn-reg-17), section 4.1.
 *     <li>OAuth 2.0 Dynamic Client Registration Management Protocol
 *         (draft-ietf-oauth-dyn-reg-management-01), section 3.1.
 * </ul>
 */
@Immutable
public final class OIDCClientInformation extends ClientInformation {


	/**
	 * The registered parameter names.
	 */
	private static final Set<String> REGISTERED_PARAMETER_NAMES;


	/**
	 * Initialises the registered parameter name set.
	 */
	static {
		Set<String> p = new HashSet<>(ClientInformation.getRegisteredParameterNames());
		p.addAll(OIDCClientMetadata.getRegisteredParameterNames());
		REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
	}


	/**
	 * Creates a new OpenID Connect client information instance.
	 *
	 * @param id              The client identifier. Must not be
	 *                        {@code null}.
	 * @param issueDate       The issue date of the client identifier,
	 *                        {@code null} if not specified.
	 * @param metadata        The OpenID Connect client metadata. Must not
	 *                        be {@code null}.
	 * @param secret          The optional client secret, {@code null} if
	 *                        not specified.
	 */
	public OIDCClientInformation(final ClientID id,
				 final Date issueDate,
				 final OIDCClientMetadata metadata,
				 final Secret secret) {

		this(id, issueDate, metadata, secret, null, null);
	}

	
	/**
	 * Creates a new OpenID Connect client information instance permitting
	 * dynamic client registration management.
	 * 
	 * @param id              The client identifier. Must not be 
	 *                        {@code null}.
	 * @param issueDate       The issue date of the client identifier,
	 *                        {@code null} if not specified.
	 * @param metadata        The OpenID Connect client metadata. Must not
	 *                        be {@code null}.
	 * @param secret          The optional client secret, {@code null} if
	 *                        not specified.
	 * @param registrationURI The client registration URI, {@code null} if
	 *                        not specified.
	 * @param accessToken     The client registration access token,
	 *                        {@code null} if not specified.
	 */
	public OIDCClientInformation(final ClientID id,
				     final Date issueDate,
				     final OIDCClientMetadata metadata,
				     final Secret secret,
				     final URI registrationURI,
				     final BearerAccessToken accessToken) {
		
		super(id, issueDate, metadata, secret, registrationURI, accessToken);
	}


	/**
	 * Gets the registered client metadata parameter names.
	 *
	 * @return The registered parameter names, as an unmodifiable set.
	 */
	public static Set<String> getRegisteredParameterNames() {

		return REGISTERED_PARAMETER_NAMES;
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

		Date issueDate = null;

		if (jsonObject.containsKey("client_id_issued_at")) {

			issueDate = new Date(JSONObjectUtils.getLong(jsonObject, "client_id_issued_at") * 1000);
		}

		OIDCClientMetadata metadata = OIDCClientMetadata.parse(jsonObject);

		Secret secret = null;

		if (jsonObject.containsKey("client_secret")) {

			String value = JSONObjectUtils.getString(jsonObject, "client_secret");

			Date exp = null;

			if (jsonObject.containsKey("client_secret_expires_at"))
				exp = new Date(JSONObjectUtils.getLong(jsonObject, "client_secret_expires_at") * 1000);

			secret = new Secret(value, exp);
		}

		URI registrationURI = null;

		if (jsonObject.containsKey("registration_client_uri")) {

			registrationURI = JSONObjectUtils.getURI(jsonObject, "registration_client_uri");
		}

		BearerAccessToken accessToken = null;

		if (jsonObject.containsKey("registration_access_token")) {

			accessToken = new BearerAccessToken(
				JSONObjectUtils.getString(jsonObject, "registration_access_token"));
		}

		return new OIDCClientInformation(id, issueDate, metadata, secret, registrationURI, accessToken);
	}
}

package com.nimbusds.oauth2.sdk.auth;


import java.util.Map;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import org.apache.commons.lang3.StringUtils;


/**
 * Base abstract class for client authentication at the Token endpoint.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 2.3.
 * </ul>
 */
public abstract class ClientAuthentication {
	
	
	/**
	 * The client authentication method.
	 */
	private final ClientAuthenticationMethod method;


	/**
	 * The client ID.
	 */
	private final ClientID clientID;
	
	
	/**
	 * Creates a new abstract client authentication.
	 *
	 * @param method   The client authentication method. Must not be
	 *                 {@code null}.
	 * @param clientID The client identifier. Must not be {@code null}.
	 */
	protected ClientAuthentication(final ClientAuthenticationMethod method, final ClientID clientID) {
	
		if (method == null)
			throw new IllegalArgumentException("The client authentication method must not be null");
		
		this.method = method;


		if (clientID == null)
			throw new IllegalArgumentException("The client identifier must not be null");

		this.clientID = clientID;
	}
	
	
	/**
	 * Gets the client authentication method.
	 *
	 * @return The client authentication method.
	 */
	public ClientAuthenticationMethod getMethod() {
	
		return method;
	}


	/**
	 * Gets the client identifier.
	 *
	 * @return The client identifier.
	 */
	public ClientID getClientID() {

		return clientID;
	}
	
	
	/**
	 * Parses the specified HTTP request for a supported client 
	 * authentication (see {@link ClientAuthenticationMethod}). This method
	 * is intended to aid parsing of authenticated 
	 * {@link com.nimbusds.oauth2.sdk.TokenRequest}s.
	 *
	 * @param httpRequest The HTTP request to parse. Must not be 
	 *                    {@code null}.
	 *
	 * @return The client authentication method, {@code null} if none or 
	 *         the method is not supported.
	 *
	 * @throws ParseException If the inferred client authentication 
	 *                        couldn't be parsed.
	 */
	public static ClientAuthentication parse(final HTTPRequest httpRequest)
		throws ParseException {
	
		// Check for client secret basic
		if (httpRequest.getAuthorization() != null && 
		    httpRequest.getAuthorization().startsWith("Basic"))

			return ClientSecretBasic.parse(httpRequest);
		
		// The other methods require HTTP POST with URL-encoded params
		if (httpRequest.getMethod() != HTTPRequest.Method.POST &&
		    ! httpRequest.getContentType().match(CommonContentTypes.APPLICATION_URLENCODED))
			return null;
		
		
		String query = httpRequest.getQuery();
		
		if (query == null)
			return null;
		
		Map<String,String> params = URLUtils.parseParameters(query);
		
		// We have client secret post
		if (StringUtils.isNotBlank(params.get("client_id")) && StringUtils.isNotBlank(params.get("client_secret")))
			return ClientSecretPost.parse(httpRequest);
		
		// Do we have a signed JWT assertion?
		if (StringUtils.isNotBlank(params.get("client_assertion")) && StringUtils.isNotBlank(params.get("client_assertion_type")))
			return JWTAuthentication.parse(httpRequest);
		else
			return null;
	}
	
	
	/**
	 * Applies the authentication to the specified HTTP request by setting 
	 * its Authorization header and/or POST entity-body parameters 
	 * (according to the implemented client authentication method).
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @throws SerializeException If the client authentication parameters
	 *                            couldn't be applied to the HTTP request.
	 */
	public abstract void applyTo(final HTTPRequest httpRequest) 
		throws SerializeException;
}

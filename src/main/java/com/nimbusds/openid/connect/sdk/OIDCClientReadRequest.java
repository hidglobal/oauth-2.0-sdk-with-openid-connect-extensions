package com.nimbusds.openid.connect.sdk;


import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * OpenID Connect client read request.
 *
 * <p>Example HTTP request:
 *
 * <pre>
 * GET /connect/register?client_id=s6BhdRkqt3 HTTP/1.1
 * Accept: application/json
 * Host: server.example.com
 * Authorization: Bearer this.is.an.access.token.value.ffx83
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, section 4.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
public class OIDCClientReadRequest extends OIDCClientRegistrationRequest {


	/**
	 * The client ID.
	 */
	private final ClientID clientID;


	/**
	 * Creates a new OpenID Connect client read request.
	 *
	 * @param clientID The client ID. Must not be {@code null}.
	 */
	public OIDCClientReadRequest(final ClientID clientID) {

		super();

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


	@Override
	public HTTPRequest toHTTPRequest(final URL url) {
	
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, url);

		Map<String,String> params = new HashMap<String,String>();

		params.put("client_id", clientID.getValue());

		httpRequest.setQuery(URLUtils.serializeParameters(params));

		return httpRequest;
	}


	/**
	 * Parses an OpenID Connect client read request from the specified HTTP
	 * GET request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The client read request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a 
	 *                        client read request.
	 */
	public static OIDCClientReadRequest parse(final HTTPRequest httpRequest)
		throws ParseException {

		httpRequest.ensureMethod(HTTPRequest.Method.GET);

		Map<String,String> params = httpRequest.getQueryParameters();

		String clientIDString = params.get("client_id");

		if (clientIDString == null)
			throw new ParseException("Missing client_id");	

		OIDCClientReadRequest req = new OIDCClientReadRequest(new ClientID(clientIDString));

		String authzHeaderValue = httpRequest.getAuthorization();

		if (StringUtils.isNotBlank(authzHeaderValue))
			req.setAccessToken(BearerAccessToken.parse(authzHeaderValue));

		return req;
	}
}

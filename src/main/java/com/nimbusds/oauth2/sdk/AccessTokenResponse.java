package com.nimbusds.oauth2.sdk;


import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * Access token response from the Token endpoint.
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 200 OK
 * Content-Type: application/json;charset=UTF-8
 * Cache-Control: no-store
 * Pragma: no-cache
 *
 * {
 *   "access_token"      : "2YotnFZFEjr1zCsicMWpAA",
 *   "token_type"        : "example",
 *   "expires_in"        : 3600,
 *   "refresh_token"     : "tGzv3JOkF0XG5Qx2TlKWIA",
 *   "example_parameter" : "example_value"
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 4.1.4, 4.3.3,  4.4.3 and 5.1.
 * </ul>
 */
@Immutable
public class AccessTokenResponse extends TokenResponse implements SuccessResponse {


	/**
	 * The tokens.
	 */
	private final Tokens tokens;


	/**
	 * Optional custom parameters.
	 */
	private final Map<String,Object> customParams;


	/**
	 * Creates a new access token response.
	 *
	 * @param tokens The tokens. Must not be {@code null}.
	 */
	public AccessTokenResponse(final Tokens tokens) {

		this(tokens, null);
	}


	/**
	 * Creates a new access token response.
	 *
	 * @param tokens       The tokens. Must not be {@code null}.
	 * @param customParams Optional custom parameters, {@code null} if
	 *                     none.
	 */
	public AccessTokenResponse(final Tokens tokens,
				   final Map<String,Object> customParams) {

		if (tokens == null)
			throw new IllegalArgumentException("The tokens must not be null");

		this.tokens = tokens;

		this.customParams = customParams;
	}


	@Override
	public boolean indicatesSuccess() {

		return true;
	}


	/**
	 * Returns the tokens.
	 *
	 * @return The tokens.
	 */
	public Tokens getTokens() {

		return tokens;
	}


	/**
	 * Returns the custom parameters.
	 *
	 * @return The custom parameters, as a unmodifiable map, empty map if
	 *         none.
	 */
	public Map<String,Object> getCustomParams() {

		if (customParams == null)
			return Collections.emptyMap();

		return Collections.unmodifiableMap(customParams);
	}
	
	
	/**
	 * Returns a JSON object representation of this access token response.
	 *
	 * <p>Example JSON object:
	 *
	 * <pre>
	 * {
	 *   "access_token"  : "SlAV32hkKG",
	 *   "token_type"    : "Bearer",
	 *   "refresh_token" : "8xLOxBtZp8",
	 *   "expires_in"    : 3600
	 * }
	 * </pre>
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {
	
		JSONObject o = tokens.toJSONObject();

		if (customParams != null)
			o.putAll(customParams);
		
		return o;
	}
	
	
	@Override
	public HTTPResponse toHTTPResponse() {
	
		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
		
		httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
		httpResponse.setCacheControl("no-store");
		httpResponse.setPragma("no-cache");
		
		httpResponse.setContent(toJSONObject().toString());
		
		return httpResponse;
	}
	
	
	/**
	 * Parses an access token response from the specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The access token response.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an
	 *                        access token response.
	 */
	public static AccessTokenResponse parse(final JSONObject jsonObject)
		throws ParseException {
		
		Tokens tokens = Tokens.parse(jsonObject);

		// Determine the custom param names
		Set<String> paramNames = tokens.getParameterNames();
		Set<String> customParamNames = jsonObject.keySet();
		customParamNames.removeAll(paramNames);

		Map<String,Object> customParams = null;

		if (! customParamNames.isEmpty()) {

			customParams = new HashMap<>();

			for (String name: customParamNames) {
				customParams.put(name, jsonObject.get(name));
			}
		}
		
		return new AccessTokenResponse(tokens, customParams);
	}
	
	
	/**
	 * Parses an access token response from the specified HTTP response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The access token response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an 
	 *                        access token response.
	 */
	public static AccessTokenResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		httpResponse.ensureStatusCode(HTTPResponse.SC_OK);
		JSONObject jsonObject = httpResponse.getContentAsJSONObject();
		return parse(jsonObject);
	}
}

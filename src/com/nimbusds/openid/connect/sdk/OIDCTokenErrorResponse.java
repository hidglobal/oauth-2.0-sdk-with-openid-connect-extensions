package com.nimbusds.openid.connect.sdk;


import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * OpenID Connect token error response. This class is immutable.
 *
 * <p>Standard token errors:
 *
 * <ul>
 *     <li>{@link com.nimbusds.oauth2.sdk.OAuth2Error#INVALID_REQUEST}
 *     <li>{@link com.nimbusds.oauth2.sdk.OAuth2Error#INVALID_CLIENT}
 *     <li>{@link com.nimbusds.oauth2.sdk.OAuth2Error#INVALID_GRANT}
 *     <li>{@link com.nimbusds.oauth2.sdk.OAuth2Error#UNAUTHORIZED_CLIENT}
 *     <li>{@link com.nimbusds.oauth2.sdk.OAuth2Error#UNSUPPORTED_GRANT_TYPE}
 *     <li>{@link com.nimbusds.oauth2.sdk.OAuth2Error#INVALID_SCOPE}
 * </ul>
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 400 Bad Request
 * Content-Type: application/json
 * Cache-Control: no-store
 * Pragma: no-cache
 * 
 * {
 *  "error": "invalid_request"
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.1.3.
 *     <li>OpenID Connect Standard 1.0, section 2.3.5.2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-30)
 */
@Immutable
public class OIDCTokenErrorResponse 
	extends TokenErrorResponse
	implements OIDCTokenResponse {


	/**
	 * Creates a new OpenID Connect token error response. No OAuth 2.0 
	 * error is specified.
	 */
	private OIDCTokenErrorResponse() {

		super();
	}


	/**
	 * Creates a new OpenID Connect token error response.
	 *
	 * @param error The error. Should match one of the 
	 *              {@link #getStandardErrors standard errors} for a token 
	 *              error response. Must not be {@code null}.
	 */
	public OIDCTokenErrorResponse(final ErrorObject error) {
	
		super(error);
	}


	/**
	 * Parses an OpenID Connect token error response from the specified 
	 * JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Its status code must not
	 *                   be 200 (OK). Must not be {@code null}.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an 
	 *                        OpenID Connect token error response.
	 */
	public static OIDCTokenErrorResponse parse(final JSONObject jsonObject)
		throws ParseException {

		ErrorObject error = TokenErrorResponse.parse(jsonObject).getErrorObject();

		if (error != null)
			return new OIDCTokenErrorResponse(error);

		else
			return new OIDCTokenErrorResponse();
	}


	/**
	 * Parses an OpenID Connect token error response from the specified 
	 * HTTP response.
	 *
	 * @param httpResponse The HTTP response to parse. Its status code must
	 *                     not be 200 (OK). Must not be {@code null}.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an 
	 *                        OpenID Connect token error response.
	 */
	public static OIDCTokenErrorResponse parse(final HTTPResponse httpResponse)
		throws ParseException {

		ErrorObject error = TokenErrorResponse.parse(httpResponse).getErrorObject();

		if (error != null)
			return new OIDCTokenErrorResponse(error);

		else
			return new OIDCTokenErrorResponse();
	}
}

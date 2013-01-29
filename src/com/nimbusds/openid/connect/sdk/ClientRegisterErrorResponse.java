package com.nimbusds.openid.connect.sdk;


import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.BearerTokenError;
import com.nimbusds.oauth2.sdk.ErrorResponse;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;

import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * OpenID Connect client register error response. This class is immutable.
 *
 * <p>Standard errors:
 *
 * <ul>
 *     <li>OAuth 2.0 Bearer Token errors:
 *         <ul>
 *             <li>{@link com.nimbusds.oauth2.sdk.BearerTokenError#MISSING_TOKEN}
 *             <li>{@link com.nimbusds.oauth2.sdk.BearerTokenError#INVALID_REQUEST}
 *             <li>{@link com.nimbusds.oauth2.sdk.BearerTokenError#INVALID_TOKEN}
 *             <li>{@link com.nimbusds.oauth2.sdk.BearerTokenError#INSUFFICIENT_SCOPE}
 *          </ul>
 *     <li>OpenID Connect client registration specific errors:
 *         <ul>
 *             <li>{@link OIDCError#INVALID_OPERATION}
 *             <li>{@link OIDCError#INVALID_REDIRECT_URI}
 *             <li>{@link OIDCError#INVALID_CONFIGURATION_PARAMETER}
 *         </ul>
 * </ul>
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 400 Bad Request
 * Content-Type: application/json
 * Cache-Control: no-store
 *
 * {
 *   "error_code"        : "invalid_operation",
 *   "error_description" : "Invalid or unsupported client registration operation"
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, section 2.3.
 *     <li>OAuth 2.0 Bearer Token Usage (RFC 6750), section 3.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-29)
 */
@Immutable
public final class ClientRegisterErrorResponse 
	extends ClientRegisterResponse
	implements ErrorResponse {


	/**
	 * Gets the standard errors for an OpenID Connect client register error
	 * response.
	 *
	 * @return The standard errors, as a read-only set.
	 */
	public static Set<OAuth2Error> getStandardErrors() {
		
		Set<OAuth2Error> stdErrors = new HashSet<OAuth2Error>();
		stdErrors.add(BearerTokenError.MISSING_TOKEN);
		stdErrors.add(BearerTokenError.INVALID_REQUEST);
		stdErrors.add(BearerTokenError.INVALID_TOKEN);
		stdErrors.add(BearerTokenError.INSUFFICIENT_SCOPE);
		stdErrors.add(OIDCError.INVALID_OPERATION);
		stdErrors.add(OIDCError.INVALID_REDIRECT_URI);
		stdErrors.add(OIDCError.INVALID_CONFIGURATION_PARAMETER);

		return Collections.unmodifiableSet(stdErrors);
	}


	/**
	 * The error.
	 */
	private final OAuth2Error error;


	/**
	 * Creates a new OpenID Connect client register error response. No 
	 * error is specified.
	 */
	private ClientRegisterErrorResponse() {

		error = null;
	}


	/**
	 * Creates a new OpenID Connect client register error response.
	 *
	 * @param error The error. Should match one of the 
	 *              {@link #getStandardErrors standard errors} for an
	 *              OpenID Connect client register error response. Must not
	 *              be {@code null}.
	 */
	public ClientRegisterErrorResponse(final OAuth2Error error) {

		if (error == null)
			throw new IllegalArgumentException("The error must not be null");

		this.error = error;
	}


	@Override
	public OAuth2Error getOAuth2Error() {

		return error;
	}


	@Override
	public JSONObject toJSONObject() {

		if (error == null)
			return null;

		// JSON object only on OIDC reg specific errors
		if (! error.equals(OIDCError.INVALID_OPERATION) &&
		    ! error.equals(OIDCError.INVALID_REDIRECT_URI) &&
		    ! error.equals(OIDCError.INVALID_CONFIGURATION_PARAMETER))
			return null;

		JSONObject jsonObject = new JSONObject();

		jsonObject.put("error", error.getCode());

		if (error.getDescription() != null)
			jsonObject.put("error_description", error.getDescription());

		return jsonObject;
	}


	@Override
	public HTTPResponse toHTTPResponse() {

		HTTPResponse httpResponse = null;

		if (error.getHTTPStatusCode() > 0)
			httpResponse = new HTTPResponse(error.getHTTPStatusCode());
		else
			httpResponse = new HTTPResponse(HTTPResponse.SC_BAD_REQUEST);

		if (error instanceof BearerTokenError) {

			httpResponse.setWWWAuthenticate(((BearerTokenError)error).toWWWAuthenticateHeader());
		}
		else {
			JSONObject jsonObject = toJSONObject();

			if (jsonObject != null) {

				httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
				httpResponse.setCacheControl("no-store");
				httpResponse.setContent(jsonObject.toString());
			}
		}

		return httpResponse;
	}


	/**
	 * Parses an OpenID Connect client register error response from the
	 * specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The OpenID Connect client register error response.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an
	 *                        OpenID Connect client register error 
	 *                        response.
	 */
	public static ClientRegisterErrorResponse parse(final JSONObject jsonObject)
		throws ParseException {

		String errorCode = JSONObjectUtils.getString(jsonObject, "error_code");

		String errorDescription = null;

		if (jsonObject.containsKey("error_description"))
			errorDescription = JSONObjectUtils.getString(jsonObject, "error_description");

		OAuth2Error error = new OAuth2Error(errorCode, errorDescription, HTTPResponse.SC_BAD_REQUEST);

		return new ClientRegisterErrorResponse(error);
	}


	/**
	 * Parses an OpenID Connect client register error response from the
	 * specified HTTP response.
	 *
	 * @param httpResponse The HTTP response to parse. Must not be 
	 *                     {@code null}.
	 *
	 * @return The OpenID Connect client register error response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an
	 *                        OpenID Connect client register error 
	 *                        response.
	 */
	public static ClientRegisterErrorResponse parse(final HTTPResponse httpResponse)
		throws ParseException {

		httpResponse.ensureStatusCodeNotOK();

		// OAuth 2.0 Bearer token error?
		if (httpResponse.getWWWAuthenticate() != null) {

			BearerTokenError error = BearerTokenError.parse(httpResponse.getWWWAuthenticate());

			return new ClientRegisterErrorResponse(error);
		}

		// Client reg specific error?
		if (httpResponse.getStatusCode() == HTTPResponse.SC_BAD_REQUEST &&
		    httpResponse.getContentType() != null &&
		    httpResponse.getContentType().equals(CommonContentTypes.APPLICATION_JSON)) {

			JSONObject jsonObject = httpResponse.getContentAsJSONObject();

			return parse(jsonObject);
		}

		// Other error
		return new ClientRegisterErrorResponse();
	}
}

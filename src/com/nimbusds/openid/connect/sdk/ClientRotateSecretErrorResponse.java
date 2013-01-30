package com.nimbusds.openid.connect.sdk;


import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.BearerTokenError;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ErrorResponse;
import com.nimbusds.oauth2.sdk.ParseException;

import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * OpenID Connect client rotate secret error response. This class is immutable.
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
 * @version $version$ (2013-01-30)
 */
@Immutable
public final class ClientRotateSecretErrorResponse 
	extends ClientRotateSecretResponse
	implements ErrorResponse {


	/**
	 * Gets the standard errors for an OpenID Connect client rotate secret
	 * error response.
	 *
	 * @return The standard errors, as a read-only set.
	 */
	public static Set<ErrorObject> getStandardErrors() {
		
		Set<ErrorObject> stdErrors = new HashSet<ErrorObject>();
		stdErrors.add(BearerTokenError.MISSING_TOKEN);
		stdErrors.add(BearerTokenError.INVALID_REQUEST);
		stdErrors.add(BearerTokenError.INVALID_TOKEN);
		stdErrors.add(BearerTokenError.INSUFFICIENT_SCOPE);
		stdErrors.add(OIDCError.INVALID_OPERATION);
		stdErrors.add(OIDCError.INVALID_CONFIGURATION_PARAMETER);

		return Collections.unmodifiableSet(stdErrors);
	}


	/**
	 * The error.
	 */
	private final ErrorObject error;


	/**
	 * Creates a new OpenID Connect client rotate secret error response. No 
	 * error is specified.
	 */
	private ClientRotateSecretErrorResponse() {

		error = null;
	}


	/**
	 * Creates a new OpenID Connect client rotate secret error response.
	 *
	 * @param error The error. Should match one of the 
	 *              {@link #getStandardErrors standard errors} for an
	 *              OpenID Connect client rotate secret error response. 
	 *              Must not be {@code null}.
	 */
	public ClientRotateSecretErrorResponse(final ErrorObject error) {

		if (error == null)
			throw new IllegalArgumentException("The error must not be null");

		this.error = error;
	}


	@Override
	public ErrorObject getErrorObject() {

		return error;
	}


	@Override
	public JSONObject toJSONObject() {

		if (error == null)
			return null;

		// JSON object only on OIDC reg specific errors
		if (! error.equals(OIDCError.INVALID_OPERATION) &&
		    ! error.equals(OIDCError.INVALID_CONFIGURATION_PARAMETER))
			return null;

		JSONObject jsonObject = new JSONObject();

		jsonObject.put("error", error.getCode());

		if (error.getDescription() != null)
			jsonObject.put("error_description", error.getDescription());

		return jsonObject;
	}


	/**
	 * Parses an OpenID Connect client rotate secret error response from 
	 * the specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The OpenID Connect client rotate secret error response.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an
	 *                        OpenID Connect client rotate secret error 
	 *                        response.
	 */
	public static ClientRotateSecretErrorResponse parse(final JSONObject jsonObject)
		throws ParseException {

		ErrorObject error = ClientRegistrationResponse.parseError(jsonObject);

		return new ClientRotateSecretErrorResponse(error);
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
	public static ClientRotateSecretErrorResponse parse(final HTTPResponse httpResponse)
		throws ParseException {

		ErrorObject error = ClientRegistrationResponse.parseError(httpResponse);

		if (error != null)
			return new ClientRotateSecretErrorResponse(error);
		else
			return new ClientRotateSecretErrorResponse();
	}
}

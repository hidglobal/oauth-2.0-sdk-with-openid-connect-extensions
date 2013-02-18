package com.nimbusds.openid.connect.sdk;


import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ErrorResponse;
import com.nimbusds.oauth2.sdk.ParseException;

import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import com.nimbusds.oauth2.sdk.token.BearerTokenError;

import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;


/**
 * OpenID Connect client registration error response. This class is immutable.
 *
 * <p>Standard errors:
 *
 * <ul>
 *     <li>OAuth 2.0 Bearer Token errors:
 *         <ul>
 *             <li>{@link com.nimbusds.oauth2.sdk.token.BearerTokenError#MISSING_TOKEN}
 *             <li>{@link com.nimbusds.oauth2.sdk.token.BearerTokenError#INVALID_REQUEST}
 *             <li>{@link com.nimbusds.oauth2.sdk.token.BearerTokenError#INVALID_TOKEN}
 *             <li>{@link com.nimbusds.oauth2.sdk.token.BearerTokenError#INSUFFICIENT_SCOPE}
 *          </ul>
 *     <li>OpenID Connect specific errors:
 *         <ul>
 *             <li>{@link OIDCError#INVALID_CLIENT_ID}
 *             <li>{@link OIDCError#INVALID_REDIRECT_URI}
 *             <li>{@link OIDCError#INVALID_CONFIGURATION_PARAMETER}
 *         </ul>
 * </ul>
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 401 Unauthorized
 * WWW-Authenticate: Bearer realm="example.com",
 *                   error="invalid_token",
 *                   error_description="The access token expired"
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, section 3.3.
 *     <li>OAuth 2.0 Bearer Token Usage (RFC 6750), section 3.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-02-18)
 */
@Immutable
public class OIDCClientRegistrationErrorResponse 
	extends OIDCClientRegistrationResponse
	implements ErrorResponse {


	/**
	 * Gets the standard errors for an OpenID Connect client registration
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
		stdErrors.add(OIDCError.INVALID_CLIENT_ID);
		stdErrors.add(OIDCError.INVALID_REDIRECT_URI);
		stdErrors.add(OIDCError.INVALID_CONFIGURATION_PARAMETER);

		return Collections.unmodifiableSet(stdErrors);
	}


	/**
	 * The underlying error.
	 */
	private final ErrorObject error;


	/**
	 * Creates a new OpenID Connect client registration error response.
	 *
	 * @param error The error. Should match one of the 
	 *              {@link #getStandardErrors standard errors} for a client
	 *              registration error response. Must not be {@code null}.
	 */
	public OIDCClientRegistrationErrorResponse(final ErrorObject error) {

		if (error == null)
			throw new IllegalArgumentException("The error must not be null");

		this.error = error;
	}


	@Override
	public ErrorObject getErrorObject() {

		return error;
	}


	/**
	 * Returns the HTTP response for this OpenID Connect client 
	 * registration error response.
	 *
	 * <p>Example HTTP response:
	 *
	 * <pre>
	 * HTTP/1.1 401 Unauthorized
	 * WWW-Authenticate: Bearer realm="example.com",
	 *                   error="invalid_token",
	 *                   error_description="The access token expired"
	 * </pre>
	 *
	 * @return The HTTP response.
	 */
	@Override
	public HTTPResponse toHTTPResponse() {

		HTTPResponse httpResponse = null;

		if (error.getHTTPStatusCode() > 0)
			httpResponse = new HTTPResponse(error.getHTTPStatusCode());
		else
			httpResponse = new HTTPResponse(HTTPResponse.SC_BAD_REQUEST);

		// Add the WWW-Authenticate header
		if (error != null && error instanceof BearerTokenError) {

			BearerTokenError bte = (BearerTokenError)error;

			httpResponse.setWWWAuthenticate(bte.toWWWAuthenticateHeader());
		}
		else {
			JSONObject jsonObject = new JSONObject();

			if (error.getCode() != null)
				jsonObject.put("error", error.getCode());

			if (error.getDescription() != null)
				jsonObject.put("error_description", error.getDescription());

			httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);

			httpResponse.setContent(jsonObject.toString());
		}

		return httpResponse;
	}


	/**
	 * Parses an OpenID Connect client registration error response from the
	 * specified HTTP response.
	 *
	 * <p>Note: The HTTP status code is not checked for matching the error
	 * code semantics.
	 *
	 * @param httpResponse The HTTP response to parse. Its status code must
	 *                     not be 200 (OK). Must not be {@code null}.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an 
	 *                        OpenID Connect client registration error 
	 *                        response.
	 */
	public static OIDCClientRegistrationErrorResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		httpResponse.ensureStatusCodeNotOK();

		ErrorObject error = null;

		String wwwAuth = httpResponse.getWWWAuthenticate();
		
		if (StringUtils.isDefined(wwwAuth)) {

			error = BearerTokenError.parse(wwwAuth);
		}
		else {
			JSONObject jsonObject = httpResponse.getContentAsJSONObject();

			String code = JSONObjectUtils.getString(jsonObject, "error");

			String description = null;

			if (jsonObject.containsKey("error_description"))
				description = JSONObjectUtils.getString(jsonObject, "error_description");

			error = new ErrorObject(code, description);
		}

		return new OIDCClientRegistrationErrorResponse(error);
	}
}
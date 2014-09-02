package com.nimbusds.oauth2.sdk.client;


import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import net.jcip.annotations.Immutable;

import org.apache.commons.lang3.StringUtils;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ErrorResponse;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * Client registration error response.
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
 *             <li>{@link RegistrationError#INVALID_REDIRECT_URI}
 *             <li>{@link RegistrationError#INVALID_CLIENT_METADATA}
 *             <li>{@link RegistrationError#INVALID_SOFTWARE_STATEMENT}
 *             <li>{@link RegistrationError#UNAPPROVED_SOFTWARE_STATEMENT}
 *         </ul>
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
 *  "error":"invalid_redirect_uri",
 *  "error_description":"The redirection URI of http://sketchy.example.com is not allowed for this server."
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol 
 *         (draft-ietf-oauth-dyn-reg-20), section 4.2.
 *     <li>OAuth 2.0 Bearer Token Usage (RFC 6750), section 3.1.
 * </ul>
 */
@Immutable
public class ClientRegistrationErrorResponse 
	extends ClientRegistrationResponse
	implements ErrorResponse {


	/**
	 * Gets the standard errors for a client registration error response.
	 *
	 * @return The standard errors, as a read-only set.
	 */
	public static Set<ErrorObject> getStandardErrors() {
		
		Set<ErrorObject> stdErrors = new HashSet<>();
		stdErrors.add(BearerTokenError.MISSING_TOKEN);
		stdErrors.add(BearerTokenError.INVALID_REQUEST);
		stdErrors.add(BearerTokenError.INVALID_TOKEN);
		stdErrors.add(BearerTokenError.INSUFFICIENT_SCOPE);
		stdErrors.add(RegistrationError.INVALID_REDIRECT_URI);
		stdErrors.add(RegistrationError.INVALID_CLIENT_METADATA);
		stdErrors.add(RegistrationError.INVALID_SOFTWARE_STATEMENT);
		stdErrors.add(RegistrationError.UNAPPROVED_SOFTWARE_STATEMENT);

		return Collections.unmodifiableSet(stdErrors);
	}


	/**
	 * The underlying error.
	 */
	private final ErrorObject error;


	/**
	 * Creates a new client registration error response.
	 *
	 * @param error The error. Should match one of the 
	 *              {@link #getStandardErrors standard errors} for a client
	 *              registration error response. Must not be {@code null}.
	 */
	public ClientRegistrationErrorResponse(final ErrorObject error) {

		if (error == null)
			throw new IllegalArgumentException("The error must not be null");

		this.error = error;
	}


	@Override
	public ErrorObject getErrorObject() {

		return error;
	}


	/**
	 * Returns the HTTP response for this client registration error 
	 * response.
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
	 *  "error":"invalid_redirect_uri",
	 *  "error_description":"The redirection URI of http://sketchy.example.com is not allowed for this server."
	 * }
	 * </pre>
	 *
	 * @return The HTTP response.
	 */
	@Override
	public HTTPResponse toHTTPResponse() {

		HTTPResponse httpResponse;

		if (error.getHTTPStatusCode() > 0) {
			httpResponse = new HTTPResponse(error.getHTTPStatusCode());
		} else {
			httpResponse = new HTTPResponse(HTTPResponse.SC_BAD_REQUEST);
		}

		// Add the WWW-Authenticate header
		if (error instanceof BearerTokenError) {

			BearerTokenError bte = (BearerTokenError)error;

			httpResponse.setWWWAuthenticate(bte.toWWWAuthenticateHeader());

		} else {
			JSONObject jsonObject = new JSONObject();

			if (error.getCode() != null)
				jsonObject.put("error", error.getCode());

			if (error.getDescription() != null)
				jsonObject.put("error_description", error.getDescription());

			httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);

			httpResponse.setContent(jsonObject.toString());
		}
		
		httpResponse.setCacheControl("no-store");
		httpResponse.setPragma("no-cache");

		return httpResponse;
	}


	/**
	 * Parses a client registration error response from the specified HTTP 
	 * response.
	 *
	 * <p>Note: The HTTP status code is not checked for matching the error
	 * code semantics.
	 *
	 * @param httpResponse The HTTP response to parse. Its status code must
	 *                     not be 200 (OK). Must not be {@code null}.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to a
	 *                        client registration error response.
	 */
	public static ClientRegistrationErrorResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		httpResponse.ensureStatusCodeNotOK();

		ErrorObject error;

		String wwwAuth = httpResponse.getWWWAuthenticate();
		
		if (StringUtils.isNotBlank(wwwAuth)) {

			error = BearerTokenError.parse(wwwAuth);

		} else {
			
			String code = null;
			String description = null;
			
			if (CommonContentTypes.APPLICATION_JSON.match(httpResponse.getContentType())) {
				
				JSONObject jsonObject = httpResponse.getContentAsJSONObject();

				code = JSONObjectUtils.getString(jsonObject, "error");

				if (jsonObject.containsKey("error_description"))
					description = JSONObjectUtils.getString(jsonObject, "error_description");
			}
			
			error = new ErrorObject(code, description, httpResponse.getStatusCode());
		}

		return new ClientRegistrationErrorResponse(error);
	}
}
package com.nimbusds.oauth2.sdk;


import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_FORBIDDEN;
import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_UNAUTHORIZED;

import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import net.jcip.annotations.Immutable;


/**
 * Token introspection error response.
 *
 * <p>Standard errors:
 *
 * <ul>
 *     <li>{@link OAuth2Error#INVALID_REQUEST}
 *     <li>{@link OAuth2Error#INVALID_CLIENT}
 *     <li>{@link BearerTokenError#MISSING_TOKEN}
 *     <li>{@link BearerTokenError#INVALID_REQUEST}
 *     <li>{@link BearerTokenError#INVALID_TOKEN}
 *     <li>{@link BearerTokenError#INSUFFICIENT_SCOPE}
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
 *     <li>OAuth 2.0 Token Introspection (RFC 7662).
 * </ul>
 */
@Immutable
public class TokenIntrospectionErrorResponse extends TokenIntrospectionResponse implements ErrorResponse {


	/**
	 * The standard errors for a token introspection error response.
	 */
	private static final Set<ErrorObject> STANDARD_ERRORS;


	static {
		Set<ErrorObject> errors = new HashSet<>();
		errors.add(OAuth2Error.INVALID_REQUEST);
		errors.add(OAuth2Error.INVALID_CLIENT);
		errors.add(BearerTokenError.MISSING_TOKEN);
		errors.add(BearerTokenError.INVALID_REQUEST);
		errors.add(BearerTokenError.INVALID_TOKEN);
		errors.add(BearerTokenError.INSUFFICIENT_SCOPE);
		STANDARD_ERRORS = Collections.unmodifiableSet(errors);
	}


	/**
	 * Gets the standard  errors for a token introspection error response.
	 *
	 * @return The standard errors, as a read-only set.
	 */
	public static Set<ErrorObject> getStandardErrors() {

		return STANDARD_ERRORS;
	}


	/**
	 * The error.
	 */
	private final ErrorObject error;


	/**
	 * Creates a new token introspection error response.
	 *
	 * @param error The error, {@code null} if not specified.
	 */
	public TokenIntrospectionErrorResponse(final ErrorObject error) {

		this.error = error;
	}


	@Override
	public ErrorObject getErrorObject() {

		return error;
	}


	@Override
	public boolean indicatesSuccess() {

		return false;
	}


	@Override
	public HTTPResponse toHTTPResponse() {

		// Determine HTTP status code
		int statusCode = error != null && error.getHTTPStatusCode() > 0 ?
			error.getHTTPStatusCode() : HTTPResponse.SC_BAD_REQUEST;

		HTTPResponse httpResponse = new HTTPResponse(statusCode);

		if (error == null) {
			return httpResponse;
		}

		// Print error object if available
		if (error instanceof BearerTokenError) {
			httpResponse.setWWWAuthenticate(((BearerTokenError) error).toWWWAuthenticateHeader());
		}

		httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
		httpResponse.setCacheControl("no-store");
		httpResponse.setPragma("no-cache");
		httpResponse.setContent(error.toJSONObject().toJSONString());

		return httpResponse;
	}


	/**
	 * Parses a token introspection error response from the specified HTTP
	 * response.
	 *
	 * @param httpResponse The HTTP response to parse. Its status code must
	 *                     not be 200 (OK). Must not be {@code null}.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to a
	 *                        token introspection error response.
	 */
	public static TokenIntrospectionErrorResponse parse(final HTTPResponse httpResponse)
		throws ParseException {

		httpResponse.ensureStatusCodeNotOK();

		String wwwAuth = httpResponse.getWWWAuthenticate();

		if ((httpResponse.getStatusCode() == SC_UNAUTHORIZED || httpResponse.getStatusCode() == SC_FORBIDDEN)
			&& wwwAuth != null && wwwAuth.toLowerCase().startsWith("bearer")) {

			try {
				return new TokenIntrospectionErrorResponse(BearerTokenError.parse(httpResponse.getWWWAuthenticate()));
			} catch (ParseException e) {
				// try generic error parse ...
			}
		}

		return new TokenIntrospectionErrorResponse(ErrorObject.parse(httpResponse));
	}
}

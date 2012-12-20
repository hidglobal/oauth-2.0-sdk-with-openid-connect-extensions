package com.nimbusds.openid.connect.sdk.messages;


import java.net.URL;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.openid.connect.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.SerializeException;

import com.nimbusds.openid.connect.sdk.http.CommonContentTypes;
import com.nimbusds.openid.connect.sdk.http.HTTPResponse;

import com.nimbusds.openid.connect.sdk.util.JSONObjectUtils;


/**
 * Client registration error response. This class is immutable.
 *
 * <p>Error codes:
 *
 * <ul>
 *     <li>OAuth 2.0 Bearer Token errors:
 *         <ul>
 *             <li>{@link ErrorCode#INVALID_REQUEST}
 *             <li>{@link ErrorCode#INVALID_TOKEN}
 *             <li>{@link ErrorCode#INSUFFICIENT_SCOPE}
 *          </ul>
 *     <li>OpenID Connect specific errors:
 *         <ul>
 *             <li>{@link ErrorCode#INVALID_TYPE}
 *             <li>{@link ErrorCode#INVALID_CLIENT_ID}
 *             <li>{@link ErrorCode#INVALID_CLIENT_SECRET}
 *             <li>{@link ErrorCode#INVALID_REDIRECT_URI}
 *             <li>{@link ErrorCode#INVALID_CONFIGURATION_PARAMETER}
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
 *  "error_code":"invalid_type",
 *  "error_description":"The value of the type parameter must be one of client_associate, rotate_secret or client_update."
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, section 2.3.
 *     <li>The OAuth 2.0 Authorization Framework: Bearer Token Usage (RFC 
 *         6750), section 3.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-12-20)
 */
@Immutable
public final class ClientRegistrationErrorResponse implements ErrorResponse {


	/**
	 * OAuth 2.0 Bearer Token error response.
	 */
	private OAuthBearerTokenErrorResponse oAuthBearerTokenError = null;


	/**
	 * Client registration error code.
	 */
	private ErrorCode errorCode = null;


	/**
	 * Gets the legal client registration specific error codes for a 
	 * client registration error response. The OAuth 2.0 bearer token
	 * error codes are not included.
	 *
	 * @return The legal client registration specific error codes, as a 
	 *         read-only set.
	 */
	public static Set<ErrorCode> getLegalClientRegistrationErrorCodes() {

		// OIDC specified error codes
		Set<ErrorCode> codes = new HashSet<ErrorCode>();
		codes.add(ErrorCode.INVALID_TYPE);
		codes.add(ErrorCode.INVALID_CLIENT_ID);
		codes.add(ErrorCode.INVALID_CLIENT_SECRET);
		codes.add(ErrorCode.INVALID_REDIRECT_URI);
		codes.add(ErrorCode.INVALID_CONFIGURATION_PARAMETER);
		
		return Collections.unmodifiableSet(codes);
	}


	/**
	 * Gets the legal error codes for a client registration error response.
	 *
	 * @return The legal error codes, as a read-only set.
	 */
	public static Set<ErrorCode> getLegalErrorCodes() {
	
		Set<ErrorCode> codes = OAuthBearerTokenErrorResponse.getLegalErrorCodes();

		codes.addAll(getLegalClientRegistrationErrorCodes());
		
		return Collections.unmodifiableSet(codes);
	}
	

	/**
	 * Creates a client registration error response indicating an OAuth 2.0
	 * Bearer Token error.
	 *
	 * @param oAuthBearerTokenError The OAuth 2.0 bearer token error.
	 *                              Must not be {@code null}.
	 */
	public ClientRegistrationErrorResponse(final OAuthBearerTokenErrorResponse oAuthBearerTokenError) {
				    
		if (oAuthBearerTokenError == null)
			throw new IllegalArgumentException("The OAuth 2.0 Bearer Token error must not be null");

		this.oAuthBearerTokenError = oAuthBearerTokenError;
	}


	/**
	 * Creates a new client registration error response indicating a
	 * registration specific error.
	 *
	 * @param errorCode The client registration error code. Must not be
	 *                  {@code null}.
	 */
	public ClientRegistrationErrorResponse(final ErrorCode errorCode) {

		if (errorCode == null)
			throw new IllegalArgumentException("The error code must not be null");

		if (! getLegalClientRegistrationErrorCodes().contains(errorCode))
			throw new IllegalArgumentException("Illegal client registration response error code: " + 
				                           errorCode.getCode());

		this.errorCode = errorCode;
	}


	/**
	 * Gets the OAuth 2.0 Bearer Token error.
	 *
	 * @return The OAuth 2.0 Bearer Token error, {@code null} if the
	 *         response indicates a registration specific error.
	 */
	public OAuthBearerTokenErrorResponse getOAuthBearerTokenError() {

		return oAuthBearerTokenError;
	}


	/**
	 * Gets the client registration specific error.
	 *
	 * @return The client registration specific error, {@code null} if the
	 *         response indicates an OAuth 2.0 Bearer Token error.
	 */
	public ErrorCode getClientRegistrationErrorCode() {

		return errorCode;
	}


	@Override
	public ErrorCode getErrorCode() {
	
		if (oAuthBearerTokenError != null)
			return oAuthBearerTokenError.getErrorCode();

		else
			return errorCode;
	}


	@Override
	public URL getErrorURI() {
	
		return null;
	}


	@Override
	public HTTPResponse toHTTPResponse()
		throws SerializeException {
	
		// OAuth 2.0 Bearer error?
		if (oAuthBearerTokenError != null)
			return oAuthBearerTokenError.toHTTPResponse();

		
		// We have a registration specific error
		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_BAD_REQUEST); // 400
		
		httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
		httpResponse.setCacheControl("no-store");

		JSONObject json = new JSONObject();

		json.put("error_code", errorCode.getCode());
		json.put("error_description", errorCode.getDescription());

		httpResponse.setContent(json.toString());
		
		return httpResponse;
	}
	
	
	/**
	 * Parses a client registration error response.
	 *
	 * @param httpResponse The HTTP response to parse. Must not be 
	 *                     {@code null}.
	 *
	 * @throws ParseException If the HTTP response cannot be parsed to a 
	 *                        valid client registration error response.
	 */
	public static ClientRegistrationErrorResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		// OAuth 2.0 Bearer error?
		if (httpResponse.getWWWAuthenticate() != null) {

			OAuthBearerTokenErrorResponse oAuthBearerTokenError =
				OAuthBearerTokenErrorResponse.parse(httpResponse);

			return new ClientRegistrationErrorResponse(oAuthBearerTokenError);
		}

		// We have a registration specific error

		httpResponse.ensureContentType(CommonContentTypes.APPLICATION_JSON);

		JSONObject json = httpResponse.getContentAsJSONObject();

		String codeString = JSONObjectUtils.getString(json, "error_code");

		ErrorCode errorCode = null;

		try {
			errorCode = ErrorCode.valueOf(codeString.toUpperCase());

		} catch (IllegalArgumentException e) {

			throw new ParseException("Invalid client registration error code: " + codeString);
		}


		if (! getLegalClientRegistrationErrorCodes().contains(errorCode))
			throw new ParseException("Illegal client registration response error code: " + 
				                 codeString);

		return new ClientRegistrationErrorResponse(errorCode);
	}
}

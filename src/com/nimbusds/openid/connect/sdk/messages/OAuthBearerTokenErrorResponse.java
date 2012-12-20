package com.nimbusds.openid.connect.sdk.messages;


import java.net.MalformedURLException;
import java.net.URL;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import net.jcip.annotations.Immutable;

import org.apache.commons.lang3.StringEscapeUtils;

import com.nimbusds.openid.connect.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.SerializeException;

import com.nimbusds.openid.connect.sdk.http.HTTPResponse;


/**
 * OAuth 2.0 Bearer Token error response. This class is immutable.
 *
 * <p>Allowed error codes:
 *
 * <ul>
 *     <li>{@link ErrorCode#INVALID_REQUEST}
 *     <li>{@link ErrorCode#INVALID_TOKEN}
 *     <li>{@link ErrorCode#INSUFFICIENT_SCOPE}
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
 *     <li>The OAuth 2.0 Authorization Framework: Bearer Token Usage (RFC 
 *         6750, section 3.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-12-20)
 */
@Immutable
public class OAuthBearerTokenErrorResponse implements ErrorResponse {


	/**
	 * The error codes for an OAuth 2.0 Bearer Token error response.
	 */
	private static final Set<ErrorCode> errorCodes = new HashSet<ErrorCode>();
	
	
	static {
		errorCodes.add(ErrorCode.INVALID_REQUEST);
		errorCodes.add(ErrorCode.INVALID_TOKEN);
		errorCodes.add(ErrorCode.INSUFFICIENT_SCOPE);
	}
	
	
	/**
	 * Regex pattern for matching the realm parameter of a WWW-Authenticate 
	 * header.
	 */
	private static final Pattern realmPattern = Pattern.compile("realm=\"([^\"]+)");

	
	/**
	 * Regex pattern for matching the error parameter of a WWW-Authenticate 
	 * header.
	 */
	private static final Pattern errorPattern = Pattern.compile("error=\"([^\"]+)");
	
	
	/**
	 * Regex pattern for matching the error URI parameter of a 
	 * WWW-Authenticate header.
	 */
	private static final Pattern errorURIPattern = Pattern.compile("error_uri=\"([^\"]+)\"");
	
	
	/**
	 * Gets the error codes for an OAuth 2.0 Bear Token error response.
	 *
	 * @return The error codes, as a read-only set.
	 */
	public static Set<ErrorCode> getErrorCodes() {
	
		return Collections.unmodifiableSet(errorCodes);
	}
	
	
	/**
	 * The authenticating realm, {@code null} if not specified.
	 */
	private final String realm;
	
	
	/**
	 * The error code, {@code null} if the client didn't provide any 
	 * authentication information in the original request.
	 */
	private final ErrorCode errorCode;
	
	
	/**
	 * Optional URL of a web page that includes additional information 
	 * about the error, {@code null} if not specified.
	 */
	private final URL errorURI;
	
	
	/**
	 * Creates a new OAuth 2.0 Bearer Token error response.
	 *
	 * @param realm     The bearer realm. May be {@code null}.
	 * @param errorCode The error code, {@code null} if the client didn't 
	 *                  provide any authentication information in the
	 *                  original request.
	 * @param errorURI  Optional URI of a web page that includes additional
	 *                  information about the error, {@code null} if not 
	 *                  specified.
	 */
	protected OAuthBearerTokenErrorResponse(final String realm, 
	                                        final ErrorCode errorCode,
						final URL errorURI) {
	
		this.realm = realm;
		this.errorCode = errorCode;
		this.errorURI = errorURI;
	}
	
	
	/**
	 * Gets the authenticating realm.
	 *
	 * @return The authenticating realm, {@code null} if not specified.
	 */
	public String getRealm() {
	
		return realm;
	}
	

	@Override
	public ErrorCode getErrorCode() {
	
		return errorCode;
	}
	
	
	@Override
	public URL getErrorURI() {
	
		return errorURI;
	}
	
	
	@Override
	public HTTPResponse toHTTPResponse()
		throws SerializeException {
	
		HTTPResponse httpResponse = null;
		
		// Set HTTP status code
		if (errorCode == null)
			httpResponse = new HTTPResponse(HTTPResponse.SC_UNAUTHORIZED); // 401
			
		else if (errorCode == ErrorCode.INVALID_REQUEST)
			httpResponse = new HTTPResponse(HTTPResponse.SC_BAD_REQUEST); // 400
		
		else if (errorCode == ErrorCode.INVALID_TOKEN)
			httpResponse = new HTTPResponse(HTTPResponse.SC_UNAUTHORIZED); // 401
		
		else if (errorCode == ErrorCode.INSUFFICIENT_SCOPE)
			httpResponse = new HTTPResponse(HTTPResponse.SC_FORBIDDEN); // 403
		
		else
			httpResponse = new HTTPResponse(HTTPResponse.SC_BAD_REQUEST); // 400
		
		
		// Compose the WWW-Authenticate header
		
		StringBuilder sb = new StringBuilder("Bearer");
		
		int numParams = 0;
		
		if (realm != null) {
			sb.append(" realm=\"");
			sb.append(StringEscapeUtils.escapeJava(realm));
			sb.append("\"");
			
			numParams++;
		}
		
		if (errorCode != null) {
			
			if (numParams > 0)
				sb.append(",");
			
			sb.append(" error=\"");
			sb.append(StringEscapeUtils.escapeJava(errorCode.getCode()));
			sb.append("\",");
			numParams++;
			
			sb.append(" error_description=\"");
			sb.append(StringEscapeUtils.escapeJava(errorCode.getDescription()));
			sb.append("\"");
			numParams++;
		}
		
		if (errorURI != null) {
		
			if (numParams > 0)
				sb.append(",");
			
			sb.append(" error_uri=\"");
			sb.append(StringEscapeUtils.escapeJava(errorURI.toString()));
			sb.append("\"");
			numParams++;
		}
		
		httpResponse.setWWWAuthenticate(sb.toString());
		
		return httpResponse;
	}
	
	
	/**
	 * Parses an OAuth 2.0 Bearer Token error response.
	 *
	 * <p>Note: The HTTP status code is not checked for matching the error
	 * code semantics.
	 *
	 * @param httpResponse The HTTP response to parse. Must not be 
	 *                     {@code null}.
	 *
	 * @throws ParseException If the HTTP response cannot be parsed to a 
	 *                        valid OAuth 2.0 Bearer Token error response.
	 */
	public static OAuthBearerTokenErrorResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		// We must have a WWW-Authenticate header set to Bearer .*
		String wwwAuth = httpResponse.getWWWAuthenticate();
		
		if (wwwAuth == null)
			throw new ParseException("Missing HTTP WWW-Authenticate header");
		
		if (! wwwAuth.regionMatches(true, 0, "Bearer", 0, "Bearer".length()))
			throw new ParseException("WWW-Authenticate scheme must be OAuth 2.0 Bearer");
		
		Matcher m = null;
		
		// Parse optional realm
		m = realmPattern.matcher(wwwAuth);
		
		String realm = null;
		
		if (m.find())
			realm = m.group(1);
		
		
		// Parse optional error code
		m = errorPattern.matcher(wwwAuth);

		ErrorCode errorCode = null;
		
		if (m.find()) {
		
			try {
				errorCode = ErrorCode.valueOf(m.group(1).toUpperCase());

			} catch (IllegalArgumentException e) {

				throw new ParseException("Invalid error code: " + m.group(1));
			}
		}
		
		// Parse optional error URI
		m = errorURIPattern.matcher(wwwAuth);
		
		URL errorURI = null;
		
		if (m.find()) {
		
			try {
				errorURI = new URL(m.group(1));
				
			} catch (MalformedURLException e) {
			
				throw new ParseException("Invalid error URI: " + m.group(1), e);
			}
		}
		
		return new OAuthBearerTokenErrorResponse(realm, errorCode, errorURI);
	}
}

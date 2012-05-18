package com.nimbusds.openid.connect.messages;


import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringEscapeUtils;

import com.nimbusds.openid.connect.ParseException;
import com.nimbusds.openid.connect.SerializeException;

import com.nimbusds.openid.connect.http.HTTPResponse;


/**
 * OAuth 2.0 Bearer Token error response.
 *
 * <p>Legal error codes:
 *
 * <ul>
 *     <li>OAuth 2.0 errors:
 *         <ul>
 *             <li>{@link ErrorCode#INVALID_REQUEST}
 *             <li>{@link ErrorCode#INVALID_TOKEN}
 *             <li>{@link ErrorCode#INSUFFICIENT_SCOPE}
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
 *     <li>OpenID Connect Messages 1.0, section 2.3.3 and 2.4.3.
 *     <li>draft-ietf-oauth-v2-bearer-19, section 3.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-03)
 */
public class OAuthBearerTokenErrorResponse implements ErrorResponse {


	/**
	 * The legal error codes for an OAuth 2.0 Bearer Token error response.
	 */
	private static final Set<ErrorCode> legalErrorCodes = new HashSet<ErrorCode>();
	
	
	static {
		// OAuth 2.0 errors
		legalErrorCodes.add(ErrorCode.INVALID_REQUEST);
		legalErrorCodes.add(ErrorCode.INVALID_TOKEN);
		legalErrorCodes.add(ErrorCode.INSUFFICIENT_SCOPE);
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
	 * Gets the legal error codes for an OAuth 2.0 Bear Token error 
	 * response.
	 *
	 * @return The legal error codes, as a read-only set.
	 */
	public static Set<ErrorCode> getLegalErrorCodes() {
	
		return Collections.unmodifiableSet(legalErrorCodes);
	}
	
	
	/**
	 * The authenticating realm, {@code null} if not specified.
	 */
	private String realm;
	
	
	/**
	 * The error code, {@code null} if the client didn't provide any 
	 * authentication information in the original request.
	 */
	private ErrorCode errorCode = null;
	
	
	/**
	 * Optional URL of a web page that includes additional information about
	 * the error.
	 */
	private URL errorURI = null;
	
	
	/**
	 * Creates a new OAuth 2.0 Bearer Token error response.
	 *
	 * @param realm     The bearer realm. May be {@code null}.
	 * @param errorCode The error code. Must match one of the 
	 *                  {@link #getLegalErrorCodes legal error codes} for
	 *                  an OAuth 2.0 Bear Token error response. It may be
	 *                  {@code null} if the client didn't provide any 
	 *                  authentication information in the original request.
	 * @param errorURI  Optional URI of a web page that includes information
	 *                  about the error, {@code null} if not specified.
	 *
	 * @throws IllegalArgumentException If the specified error code is not
	 *                                  legal for an OAuth 2.0 Bear Token
	 *                                  error response.
	 */
	protected OAuthBearerTokenErrorResponse(final String realm, 
	                                        final ErrorCode errorCode,
						final URL errorURI) {
	
		this.realm = realm;
		
		if (errorCode != null && ! legalErrorCodes.contains(errorCode))
			throw new IllegalArgumentException("Illegal error code");
			
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
	

	/**
	 * @inheritDoc
	 */
	public ErrorCode getErrorCode() {
	
		return errorCode;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public URL getErrorURI() {
	
		return errorURI;
	}
	
	
	/**
	 * @inheritDoc
	 */
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
			throw new AssertionError("Illegal error code: " + errorCode);
		
		
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
		
		final String wwwAuth = httpResponse.getWWWAuthenticate();
		
		if (wwwAuth == null)
			throw new ParseException("Missing HTTP WWW-Authenticate header");
		
		if (! wwwAuth.regionMatches(true, 0, "Bearer", 0, "Bearer".length()))
			throw new ParseException("OAuth 2.0 scheme must be Bearer");
		
		Matcher m = null;
		
		// Parse realm
		m = realmPattern.matcher(wwwAuth);
		
		String realm = null;
		
		if (m.find())
			realm = m.group(1);
		
		
		// Parse error code
		m = errorPattern.matcher(wwwAuth);
		
		if (! m.find())
			throw new ParseException("Missing or invalid error parameter in HTTP WWW-Authenticate header");
		
		ErrorCode errorCode = null;
		
		try {
			errorCode = ErrorCode.valueOf(m.group(1).toUpperCase());

		} catch (IllegalArgumentException e) {

			throw new ParseException("Invalid error code: " + m.group(1));
		}
		
		// Parse error URI
		m = errorURIPattern.matcher(wwwAuth);
		
		URL errorURI = null;
		
		if (m.find()) {
		
			try {
				errorURI = new URL(m.group(1));
				
			} catch (MalformedURLException e) {
			
				throw new ParseException("Invalid error URI: " + m.group(1), e);
			}
		}
		
		if (! getLegalErrorCodes().contains(errorCode))
			throw new ParseException("Illegal OAuth 2.0 Bearer Token response error code: " + errorCode.getCode());
		
		return new OAuthBearerTokenErrorResponse(realm, errorCode, errorURI);
	}
}

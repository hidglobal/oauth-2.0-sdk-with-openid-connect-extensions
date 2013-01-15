package com.nimbusds.oauth2.sdk;


import java.net.URL;


/**
 * General OAuth 2.0 exception.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-15)
 */
public class OAuth2Exception extends Exception {


	/**
	 * HTTP status code 302 (Found).
	 */
	public static final int HTTP_SC_FOUND = 302;


	/**
	 * HTTP status code 400 (Bad Request).
	 */
	public static final int HTTP_SC_BAD_REQUEST = 400;


	/**
	 * The associated OAuth 2.0 error, {@code null} if not specified.
	 */
	private final OAuth2Error error;


	/**
	 * The associated HTTP status code, 0 if not specified.
	 */
	private final int httpStatusCode;


	/**
	 * The redirection URI, {@code null} if not specified or redirection is
	 * not to be performed for this error. Implies a HTTP status code 302.
	 */
	private final URL redirectURI;


	/**
	 * Optional state parameter, {@code null} if not specified.
	 */
	private final State state;


	/**
	 * Creates a new OAuth 2.0 exception.
	 *
	 * @param message The exception message. May be {@code null}.
	 */
	public OAuth2Exception(final String message) {
	
		this(message, null);
	}
	
	
	/**
	 * Creates a new OAuth 2.0 exception.
	 *
	 * @param message The exception message. May be {@code null}.
	 * @param cause   The exception cause, {@code null} if not specified.
	 */
	public OAuth2Exception(final String message, final Throwable cause) {
	
		this(message, null, cause);
	}


	/**
	 * Creates a new OAuth 2.0 exception. Implies an HTTP status code
	 * {@link #HTTP_SC_BAD_REQUEST 400}.
	 *
	 * @param message The exception message. May be {@code null}.
	 * @param error   The associated OAuth 2.0 error, {@code null} if not
	 *                specified.
	 * @param cause   The exception cause, {@code null} if not specified.
	 */
	public OAuth2Exception(final String message, 
		               final OAuth2Error error,
		               final Throwable cause) {
	
		this(message, error, null, null, cause);
	}


	/**
	 * Creates a new OAuth 2.0 exception. Implies a HTTP status code
	 * {@link #HTTP_SC_FOUND 302}.
	 *
	 * @param message     The exception message. May be {@code null}.
	 * @param error       The associated OAuth 2.0 error, {@code null} if
	 *                    not specified.
	 * @param redirectURI The associated redirection URI, must not be 
	 *                    {@code null}.
	 * @param state       The optional associated state parameter, 
	 *                    {@code null} if not specified.
	 * @param cause       The exception cause, {@code null} if not
	 *                    specified.
	 */
	public OAuth2Exception(final String message, 
		               final OAuth2Error error,
		               final URL redirectURI,
		               final State state,
		               final Throwable cause) {
	
		super(message, cause);

		this.error = error;

		httpStatusCode = HTTP_SC_FOUND;

		if (redirectURI == null)
			throw new IllegalArgumentException("The redirection URI must not be null");

		this.redirectURI = redirectURI;

		this.state = state;
	}


	/**
	 * Gets the associated OAuth 2.0 error.
	 *
	 * @return The OAuth 2.0 error, {@code null} if not specified.
	 */
	public OAuth2Error getError() {

		return error;
	}


	/**
	 * Gets the associated HTTP status code.
	 *
	 * @return The HTTP status code, with possible values 
	 *         {@link #HTTP_SC_FOUND 302}, {@link #HTTP_SC_BAD_REQUEST 400}
	 *         or 0 if not specified.
	 */
	public int getHTTPStatusCode() {

		return httpStatusCode;
	}


	/**
	 * Gets the associated redirection URI. 
	 * 
	 * <p>Important: Must be verified with the client registry before 
	 * acting upon it!
	 *
	 * @return The redirection URI, {@code null} if redirection is not to
	 *         be performed for this error.
	 */
	public URL getRedirectURI() {

		return redirectURI;
	}


	/**
	 * Gets the optional associated state parameter.
	 *
	 * @return The optional state parameter, {@code null} if not specified 
	 *         or redirection is not to be performed.
	 */
	public State getState() {

		return state;
	}
}

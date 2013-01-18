package com.nimbusds.oauth2.sdk;


import java.net.MalformedURLException;
import java.net.URL;

import java.util.LinkedHashMap;
import java.util.Map;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;

import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * Authorisation request. Used to authenticate an end-user and request the
 * end-user's consent to grant the client access to a protected resource. 
 * This class is immutable.
 *
 * <p>Extending classes may define additional parameters as well as enforce
 * tighter requirements on the base parameters.
 *
 * <p>Example HTTP request:
 *
 * <pre>
 * https://server.example.com/authorize?
 * response_type=code
 * &amp;client_id=s6BhdRkqt3
 * &amp;state=xyz
 * &amp;redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 4.1.1 and 4.2.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-16)
 */
@Immutable
public class AuthorizationRequest implements OAuth2Request {


	/**
	 * The response type set (required).
	 */
	private final ResponseTypeSet rts;


	/**
	 * The client identifier (required).
	 */
	private final ClientID clientID;


	/**
	 * The redirection URI where the response will be sent (optional). 
	 */
	private final URL redirectURI;
	
	
	/**
	 * The scope (optional).
	 */
	private final Scope scope;
	
	
	/**
	 * The opaque value to maintain state between the request and the 
	 * callback (recommended).
	 */
	private final State state;
	
	
	/**
	 * Creates a new authorisation request.
	 *
	 * @param rts         The response type set. Corresponds to the 
	 *                    {@code response_type} parameter. Must not be
	 *                    {@code null}.
	 * @param clientID    The client identifier. Corresponds to the
	 *                    {@code client_id} parameter. Must not be 
	 *                    {@code null}.
	 * @param redirectURI The redirection URI. Corresponds to the optional
	 *                    {@code redirect_uri} parameter. {@code null} if
	 *                    not specified.
	 * @param scope       The request scope. Corresponds to the optional
	 *                    {@code scope} parameter. {@code null} if not
	 *                    specified.
	 * @param state       The state. Corresponds to the recommended 
	 *                    {@code state} parameter. {@code null} if not 
	 *                    specified.
	 */
	public AuthorizationRequest(final ResponseTypeSet rts,
	                            final ClientID clientID,
				    final URL redirectURI,
	                            final Scope scope,
				    final State state) {

		if (rts == null)
			throw new IllegalArgumentException("The response type set must not be null");
		
		this.rts = rts;


		if (clientID == null)
			throw new IllegalArgumentException("The client ID must not be null");
			
		this.clientID = clientID;
		
		
		this.redirectURI = redirectURI;
		this.scope = scope;
		this.state = state;
	}
	
	
	/**
	 * Gets the response type set. Corresponds to the {@code response_type}
	 * parameter.
	 *
	 * @return The response type set.
	 */
	public ResponseTypeSet getResponseTypeSet() {
	
		return rts;
	}


	/**
	 * Gets the client identifier. Corresponds to the {@code client_id} 
	 * parameter.
	 *
	 * @return The client identifier.
	 */
	public ClientID getClientID() {
	
		return clientID;
	}


	/**
	 * Gets the redirection URI. Corresponds to the optional 
	 * {@code redirection_uri} parameter.
	 *
	 * @return The redirection URI, {@code null} if not specified.
	 */
	public URL getRedirectURI() {
	
		return redirectURI;
	}
	
	
	/**
	 * Gets the scope. Corresponds to the optional {@code scope} parameter.
	 *
	 * @return The scope, {@code null} if not specified.
	 */
	public Scope getScope() {
	
		return scope;
	}
	
	
	/**
	 * Gets the state. Corresponds to the recommended {@code state} 
	 * parameter.
	 *
	 * @return The state, {@code null} if not specified.
	 */
	public State getState() {
	
		return state;
	}
	
	
	/**
	 * Returns the URL query string for this authorisation request.
	 *
	 * <p>Note that the '?' character preceding the query string in an URL
	 * is not included in the returned string.
	 *
	 * <p>Example URL query string:
	 *
	 * <pre>
	 * response_type=code
	 * &amp;client_id=s6BhdRkqt3
	 * &amp;state=xyz
	 * &amp;redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
	 * </pre>
	 * 
	 * @return The URL query string.
	 *
	 * @throws SerializeException If this authorisation request couldn't be
	 *                            serialised to an URL query string.
	 */
	public String toQueryString()
		throws SerializeException {
		
		Map <String,String> params = new LinkedHashMap<String,String>();
		
		params.put("response_type", rts.toString());
		params.put("client_id", clientID.getValue());

		if (redirectURI != null)
			params.put("redirect_uri", redirectURI.toString());

		if (scope != null)
			params.put("scope", scope.toString());
		
		if (state != null)
			params.put("state", state.getValue());
		
		return URLUtils.serializeParameters(params);
	}
	
	
	/**
	 * Returns the matching HTTP request.
	 *
	 * @param method The HTTP request method which can be GET or POST. Must
	 *               not be {@code null}.
	 *
	 * @return The HTTP request.
	 *
	 * @throws SerializeException If the authorisation request message
	 *                            couldn't be serialised to an HTTP  
	 *                            request.
	 */
	public HTTPRequest toHTTPRequest(final HTTPRequest.Method method)
		throws SerializeException {
		
		HTTPRequest httpRequest;
		
		if (method.equals(HTTPRequest.Method.GET))
			httpRequest = new HTTPRequest(HTTPRequest.Method.GET);
		else
			httpRequest = new HTTPRequest(HTTPRequest.Method.POST);
		
		httpRequest.setQuery(toQueryString());
		
		return httpRequest;
	}
	
	
	/**
	 * Returns the matching HTTP GET request.
	 *
	 * @return The HTTP request.
	 *
	 * @throws SerializeException If the authorisation request message
	 *                            couldn't be serialised to an HTTP GET 
	 *                            request.
	 */
	@Override
	public HTTPRequest toHTTPRequest()
		throws SerializeException {
	
		return toHTTPRequest(HTTPRequest.Method.GET);
	}
	
	
	/**
	 * Parses an authorisation request from the specified URL query string.
	 *
	 * <p>Example URL query string:
	 *
	 * <pre>
	 * response_type=code
	 * &amp;client_id=s6BhdRkqt3
	 * &amp;state=xyz
	 * &amp;redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
	 * </pre>
	 *
	 * @param query The URL query string. Must not be {@code null}.
	 *
	 * @return The parsed authorisation request.
	 *
	 * @throws ParseException If the query string couldn't be parsed to an 
	 *                        authorisation request.
	 */
	public static AuthorizationRequest parse(final String query)
		throws ParseException {
	
		Map <String,String> params = URLUtils.parseParameters(query);
		
		String v = null;


		// Parse mandatory client ID first
		v = params.get("client_id");
		
		if (StringUtils.isUndefined(v))
			throw new ParseException("Missing \"client_id\" parameter", 
				                 OAuth2Error.INVALID_REQUEST);

		ClientID clientID = new ClientID(v);


		// Parse optional redirect URI second
		v = params.get("redirect_uri");

		URL redirectURI = null;

		if (StringUtils.isDefined(v)) {
			
			try {
				redirectURI = new URL(v);
				
			} catch (MalformedURLException e) {
			
				throw new ParseException("Invalid \"redirect_uri\" parameter: " + e.getMessage(), 
					                 OAuth2Error.INVALID_REQUEST, e);
			}
		}


		// Parse optional state third
		State state = State.parse(params.get("state"));
		

		// Parse mandatory response type
		v = params.get("response_type");
		
		ResponseTypeSet rts = null;
		
		try {
			rts = ResponseTypeSet.parse(v);
		
		} catch (ParseException e) {
			
			throw new ParseException(e.getMessage(), 
				                 OAuth2Error.UNSUPPORTED_RESPONSE_TYPE, 
				                 redirectURI, state, e);
		}
			
		
		// Parse optional scope
		v = params.get("scope");

		Scope scope = null;
		
		if (StringUtils.isDefined(v))
			scope = Scope.parse(v);


		return new AuthorizationRequest(rts, clientID, redirectURI, scope, state);
	}
	
	
	/**
	 * Parses an authorisation request from the specified HTTP GET or HTTP
	 * POST request.
	 *
	 * <p>Example HTTP request (GET):
	 *
	 * <pre>
	 * https://server.example.com/authorize?
	 * response_type=code
	 * &amp;client_id=s6BhdRkqt3
	 * &amp;state=xyz
	 * &amp;redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
	 * </pre>
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The authorisation request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to an 
	 *                        authorisation request.
	 */
	public static AuthorizationRequest parse(final HTTPRequest httpRequest) 
		throws ParseException {
		
		String query = httpRequest.getQuery();
		
		if (query == null)
			throw new ParseException("Missing URL query string");
		
		return parse(query);
	}
}

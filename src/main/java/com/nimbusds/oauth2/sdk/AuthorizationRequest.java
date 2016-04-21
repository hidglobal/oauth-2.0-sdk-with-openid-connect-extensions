package com.nimbusds.oauth2.sdk;


import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.*;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.util.URIUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import net.jcip.annotations.Immutable;
import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang3.StringUtils;


/**
 * Authorisation request. Used to authenticate an end-user and request the
 * end-user's consent to grant the client access to a protected resource.
 * Supports custom request parameters.
 *
 * <p>Extending classes may define additional request parameters as well as 
 * enforce tighter requirements on the base parameters.
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
 *     <li>OAuth 2.0 Multiple Response Type Encoding Practices 1.0.
 *     <li>OAuth 2.0 Form Post Response Mode 1.0.
 *     <li>Proof Key for Code Exchange by OAuth Public Clients (RFC 7636).
 * </ul>
 */
@Immutable
public class AuthorizationRequest extends AbstractRequest {


	/**
	 * The registered parameter names.
	 */
	private static final Set<String> REGISTERED_PARAMETER_NAMES;


	/**
	 * Initialises the registered parameter name set.
	 */
	static {
		Set<String> p = new HashSet<>();

		p.add("response_type");
		p.add("client_id");
		p.add("redirect_uri");
		p.add("scope");
		p.add("state");
		p.add("response_mode");
		p.add("code_challenge");
		p.add("code_challenge_method");

		REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
	}


	/**
	 * The response type (required).
	 */
	private final ResponseType rt;


	/**
	 * The client identifier (required).
	 */
	private final ClientID clientID;


	/**
	 * The redirection URI where the response will be sent (optional). 
	 */
	private final URI redirectURI;
	
	
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
	 * The response mode (optional).
	 */
	private final ResponseMode rm;


	/**
	 * The authorisation code challenge for PKCE (optional).
	 */
	private final CodeChallenge codeChallenge;


	/**
	 * The authorisation code challenge method for PKCE (optional).
	 */
	private final CodeChallengeMethod codeChallengeMethod;


	/**
	 * Additional custom parameters.
	 */
	private final Map<String,String> customParams;


	/**
	 * Builder for constructing authorisation requests.
	 */
	public static class Builder {


		/**
		 * The endpoint URI (optional).
		 */
		private URI uri;


		/**
		 * The response type (required).
		 */
		private final ResponseType rt;


		/**
		 * The client identifier (required).
		 */
		private final ClientID clientID;


		/**
		 * The redirection URI where the response will be sent
		 * (optional).
		 */
		private URI redirectURI;


		/**
		 * The scope (optional).
		 */
		private Scope scope;


		/**
		 * The opaque value to maintain state between the request and
		 * the callback (recommended).
		 */
		private State state;


		/**
		 * The response mode (optional).
		 */
		private ResponseMode rm;


		/**
		 * The authorisation code challenge for PKCE (optional).
		 */
		private CodeChallenge codeChallenge;


		/**
		 * The authorisation code challenge method for PKCE (optional).
		 */
		private CodeChallengeMethod codeChallengeMethod;


		/**
		 * The additional custom parameters.
		 */
		private Map<String,String> customParams = new HashMap<>();


		/**
		 * Creates a new authorisation request builder.
		 *
		 * @param rt       The response type. Corresponds to the
		 *                 {@code response_type} parameter. Must not be
		 *                 {@code null}.
		 * @param clientID The client identifier. Corresponds to the
		 *                 {@code client_id} parameter. Must not be
		 *                 {@code null}.
		 */
		public Builder(final ResponseType rt, final ClientID clientID) {

			if (rt == null)
				throw new IllegalArgumentException("The response type must not be null");

			this.rt = rt;


			if (clientID == null)
				throw new IllegalArgumentException("The client ID must not be null");

			this.clientID = clientID;
		}


		/**
		 * Sets the redirection URI. Corresponds to the optional
		 * {@code redirection_uri} parameter.
		 *
		 * @param redirectURI The redirection URI, {@code null} if not
		 *                    specified.
		 *
		 * @return This builder.
		 */
		public Builder redirectionURI(final URI redirectURI) {

			this.redirectURI = redirectURI;
			return this;
		}


		/**
		 * Sets the scope. Corresponds to the optional {@code scope}
		 * parameter.
		 *
		 * @param scope The scope, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder scope(final Scope scope) {

			this.scope = scope;
			return this;
		}


		/**
		 * Sets the state. Corresponds to the recommended {@code state}
		 * parameter.
		 *
		 * @param state The state, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder state(final State state) {

			this.state = state;
			return this;
		}


		/**
		 * Sets the response mode. Corresponds to the optional
		 * {@code response_mode} parameter. Use of this parameter is
		 * not recommended unless a non-default response mode is
		 * requested (e.g. form_post).
		 *
		 * @param rm The response mode, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder responseMode(final ResponseMode rm) {

			this.rm = rm;
			return this;
		}


		/**
		 * Sets the code challenge for Proof Key for Code Exchange
		 * (PKCE) by public OAuth clients.
		 *
		 * @param codeChallenge       The code challenge, {@code null}
		 *                            if not specified.
		 * @param codeChallengeMethod The code challenge method,
		 *                            {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder codeChallenge(final CodeChallenge codeChallenge, final CodeChallengeMethod codeChallengeMethod) {

			this.codeChallenge = codeChallenge;
			this.codeChallengeMethod = codeChallengeMethod;
			return this;
		}


		/**
		 * Sets the specified additional custom parameter.
		 *
		 * @param name  The parameter name. Must not be {@code null}.
		 * @param value The parameter value, {@code null} if not
		 *              specified.
		 *
		 * @return This builder.
		 */
		public Builder customParameter(final String name, final String value) {

			customParams.put(name, value);
			return this;
		}


		/**
		 * Sets the URI of the endpoint (HTTP or HTTPS) for which the
		 * request is intended.
		 *
		 * @param uri The endpoint URI, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder endpointURI(final URI uri) {

			this.uri = uri;
			return this;
		}


		/**
		 * Builds a new authorisation request.
		 *
		 * @return The authorisation request.
		 */
		public AuthorizationRequest build() {

			return new AuthorizationRequest(uri, rt, rm, clientID, redirectURI, scope, state, codeChallenge, codeChallengeMethod, customParams);
		}
	}


	/**
	 * Creates a new minimal authorisation request.
	 *
	 * @param uri      The URI of the authorisation endpoint. May be
	 *                 {@code null} if the {@link #toHTTPRequest} method
	 *                 will not be used.
	 * @param rt       The response type. Corresponds to the
	 *                 {@code response_type} parameter. Must not be
	 *                 {@code null}.
	 * @param clientID The client identifier. Corresponds to the
	 *                 {@code client_id} parameter. Must not be
	 *                 {@code null}.
	 */
	public AuthorizationRequest(final URI uri,
		                    final ResponseType rt,
	                            final ClientID clientID) {

		this(uri, rt, null, clientID, null, null, null, null, null);
	}


	/**
	 * Creates a new authorisation request.
	 *
	 * @param uri                 The URI of the authorisation endpoint.
	 *                            May be {@code null} if the
	 *                            {@link #toHTTPRequest} method will not be
	 *                            used.
	 * @param rt                  The response type. Corresponds to the
	 *                            {@code response_type} parameter. Must not
	 *                            be {@code null}.
	 * @param rm                  The response mode. Corresponds to the
	 *                            optional {@code response_mode} parameter.
	 *                            Use of this parameter is not recommended
	 *                            unless a non-default response mode is
	 *                            requested (e.g. form_post).
	 * @param clientID            The client identifier. Corresponds to the
	 *                            {@code client_id} parameter. Must not be
	 *                            {@code null}.
	 * @param redirectURI         The redirection URI. Corresponds to the
	 *                            optional {@code redirect_uri} parameter.
	 *                            {@code null} if not specified.
	 * @param scope               The request scope. Corresponds to the
	 *                            optional {@code scope} parameter.
	 *                            {@code null} if not specified.
	 * @param state               The state. Corresponds to the recommended
	 *                            {@code state} parameter. {@code null} if
	 *                            not specified.
	 */
	public AuthorizationRequest(final URI uri,
		                    final ResponseType rt,
				    final ResponseMode rm,
	                            final ClientID clientID,
				    final URI redirectURI,
	                            final Scope scope,
				    final State state) {

		this(uri, rt, rm, clientID, redirectURI, scope, state, null, null);
	}


	/**
	 * Creates a new authorisation request with PKCE support.
	 *
	 * @param uri                 The URI of the authorisation endpoint.
	 *                            May be {@code null} if the
	 *                            {@link #toHTTPRequest} method will not be
	 *                            used.
	 * @param rt                  The response type. Corresponds to the
	 *                            {@code response_type} parameter. Must not
	 *                            be {@code null}.
	 * @param rm                  The response mode. Corresponds to the
	 *                            optional {@code response_mode} parameter.
	 *                            Use of this parameter is not recommended
	 *                            unless a non-default response mode is
	 *                            requested (e.g. form_post).
	 * @param clientID            The client identifier. Corresponds to the
	 *                            {@code client_id} parameter. Must not be
	 *                            {@code null}.
	 * @param redirectURI         The redirection URI. Corresponds to the
	 *                            optional {@code redirect_uri} parameter.
	 *                            {@code null} if not specified.
	 * @param scope               The request scope. Corresponds to the
	 *                            optional {@code scope} parameter.
	 *                            {@code null} if not specified.
	 * @param state               The state. Corresponds to the recommended
	 *                            {@code state} parameter. {@code null} if
	 *                            not specified.
	 * @param codeChallenge       The code challenge for PKCE, {@code null}
	 *                            if not specified.
	 * @param codeChallengeMethod The code challenge method for PKCE,
	 *                            {@code null} if not specified.
	 */
	public AuthorizationRequest(final URI uri,
		                    final ResponseType rt,
				    final ResponseMode rm,
	                            final ClientID clientID,
				    final URI redirectURI,
	                            final Scope scope,
				    final State state,
				    final CodeChallenge codeChallenge,
				    final CodeChallengeMethod codeChallengeMethod) {

		this(uri, rt, rm, clientID, redirectURI, scope, state, codeChallenge, codeChallengeMethod, Collections.<String,String>emptyMap());
	}


	/**
	 * Creates a new authorisation request with PKCE support and additional
	 * custom parameters.
	 *
	 * @param uri                 The URI of the authorisation endpoint.
	 *                            May be {@code null} if the
	 *                            {@link #toHTTPRequest} method will not be
	 *                            used.
	 * @param rt                  The response type. Corresponds to the
	 *                            {@code response_type} parameter. Must not
	 *                            be {@code null}.
	 * @param rm                  The response mode. Corresponds to the
	 *                            optional {@code response_mode} parameter.
	 *                            Use of this parameter is not recommended
	 *                            unless a non-default response mode is
	 *                            requested (e.g. form_post).
	 * @param clientID            The client identifier. Corresponds to the
	 *                            {@code client_id} parameter. Must not be
	 *                            {@code null}.
	 * @param redirectURI         The redirection URI. Corresponds to the
	 *                            optional {@code redirect_uri} parameter.
	 *                            {@code null} if not specified.
	 * @param scope               The request scope. Corresponds to the
	 *                            optional {@code scope} parameter.
	 *                            {@code null} if not specified.
	 * @param state               The state. Corresponds to the recommended
	 *                            {@code state} parameter. {@code null} if
	 *                            not specified.
	 * @param codeChallenge       The code challenge for PKCE, {@code null}
	 *                            if not specified.
	 * @param codeChallengeMethod The code challenge method for PKCE,
	 *                            {@code null} if not specified.
	 * @param customParams        Additional custom parameters, empty map
	 *                            or {@code null} if none.
	 */
	public AuthorizationRequest(final URI uri,
		                    final ResponseType rt,
				    final ResponseMode rm,
	                            final ClientID clientID,
				    final URI redirectURI,
	                            final Scope scope,
				    final State state,
				    final CodeChallenge codeChallenge,
				    final CodeChallengeMethod codeChallengeMethod,
				    final Map<String,String> customParams) {

		super(uri);

		if (rt == null)
			throw new IllegalArgumentException("The response type must not be null");

		this.rt = rt;

		this.rm = rm;


		if (clientID == null)
			throw new IllegalArgumentException("The client ID must not be null");

		this.clientID = clientID;


		this.redirectURI = redirectURI;
		this.scope = scope;
		this.state = state;

		this.codeChallenge = codeChallenge;
		this.codeChallengeMethod = codeChallengeMethod;

		if (MapUtils.isNotEmpty(customParams)) {
			this.customParams = Collections.unmodifiableMap(customParams);
		} else {
			this.customParams = Collections.emptyMap();
		}
	}


	/**
	 * Returns the registered (standard) OAuth 2.0 authorisation request
	 * parameter names.
	 *
	 * @return The registered OAuth 2.0 authorisation request parameter
	 *         names, as a unmodifiable set.
	 */
	public static Set<String> getRegisteredParameterNames() {

		return REGISTERED_PARAMETER_NAMES;
	}


	/**
	 * Gets the response type. Corresponds to the {@code response_type}
	 * parameter.
	 *
	 * @return The response type.
	 */
	public ResponseType getResponseType() {
	
		return rt;
	}


	/**
	 * Gets the optional response mode. Corresponds to the optional
	 * {@code response_mode} parameter.
	 *
	 * @return The response mode, {@code null} if not specified.
	 */
	public ResponseMode getResponseMode() {

		return rm;
	}


	/**
	 * Returns the implied response mode, determined by the optional
	 * {@code response_mode} parameter, and if that isn't specified, by
	 * the {@code response_type}.
	 *
	 * @return The implied response mode.
	 */
	public ResponseMode impliedResponseMode() {

		if (rm != null) {
			return rm;
		} else if (rt.impliesImplicitFlow()) {
			return ResponseMode.FRAGMENT;
		} else {
			return ResponseMode.QUERY;
		}
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
	public URI getRedirectionURI() {
	
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
	 * Returns the code challenge for PKCE.
	 *
	 * @return The code challenge, {@code null} if not specified.
	 */
	public CodeChallenge getCodeChallenge() {

		return codeChallenge;
	}


	/**
	 * Returns the code challenge method for PKCE.
	 *
	 * @return The code challenge method, {@code null} if not specified.
	 */
	public CodeChallengeMethod getCodeChallengeMethod() {

		return codeChallengeMethod;
	}


	/**
	 * Returns the additional custom parameters.
	 *
	 * @return The additional custom parameters as a unmodifiable map,
	 *         empty map if none.
	 */
	public Map<String,String> getCustomParameters () {

		return customParams;
	}


	/**
	 * Returns the specified custom parameter.
	 *
	 * @param name The parameter name. Must not be {@code null}.
	 *
	 * @return The parameter value, {@code null} if not specified.
	 */
	public String getCustomParameter(final String name) {

		return customParams.get(name);
	}


	/**
	 * Returns the parameters for this authorisation request.
	 *
	 * <p>Example parameters:
	 *
	 * <pre>
	 * response_type = code
	 * client_id     = s6BhdRkqt3
	 * state         = xyz
	 * redirect_uri  = https://client.example.com/cb
	 * </pre>
	 * 
	 * @return The parameters.
	 */
	public Map<String,String> toParameters() {

		Map <String,String> params = new LinkedHashMap<>();

		// Put custom params first, so they may be overwritten by std params
		params.putAll(customParams);
		
		params.put("response_type", rt.toString());
		params.put("client_id", clientID.getValue());

		if (rm != null) {
			params.put("response_mode", rm.getValue());
		}

		if (redirectURI != null)
			params.put("redirect_uri", redirectURI.toString());

		if (scope != null)
			params.put("scope", scope.toString());
		
		if (state != null)
			params.put("state", state.getValue());

		if (codeChallenge != null) {
			params.put("code_challenge", codeChallenge.getValue());

			if (codeChallengeMethod != null) {
				params.put("code_challenge_method", codeChallengeMethod.getValue());
			}
		}

		return params;
	}
	
	
	/**
	 * Returns the URI query string for this authorisation request.
	 *
	 * <p>Note that the '?' character preceding the query string in an URI
	 * is not included in the returned string.
	 *
	 * <p>Example URI query string:
	 *
	 * <pre>
	 * response_type=code
	 * &amp;client_id=s6BhdRkqt3
	 * &amp;state=xyz
	 * &amp;redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
	 * </pre>
	 * 
	 * @return The URI query string.
	 */
	public String toQueryString() {
		
		return URLUtils.serializeParameters(toParameters());
	}


	/**
	 * Returns the complete URI representation for this authorisation
	 * request, consisting of the {@link #getEndpointURI authorization
	 * endpoint URI} with the {@link #toQueryString query string} appended.
	 *
	 * <p>Example URI:
	 *
	 * <pre>
	 * https://server.example.com/authorize?
	 * response_type=code
	 * &amp;client_id=s6BhdRkqt3
	 * &amp;state=xyz
	 * &amp;redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
	 * </pre>
	 *
	 * @return The URI representation.
	 */
	public URI toURI() {

		if (getEndpointURI() == null)
			throw new SerializeException("The authorization endpoint URI is not specified");

		StringBuilder sb = new StringBuilder(getEndpointURI().toString());
		sb.append('?');
		sb.append(toQueryString());
		try {
			return new URI(sb.toString());
		} catch (URISyntaxException e) {
			throw new SerializeException("Couldn't append query string: " + e.getMessage(), e);
		}
	}
	
	
	/**
	 * Returns the matching HTTP request.
	 *
	 * @param method The HTTP request method which can be GET or POST. Must
	 *               not be {@code null}.
	 *
	 * @return The HTTP request.
	 */
	public HTTPRequest toHTTPRequest(final HTTPRequest.Method method) {
		
		if (getEndpointURI() == null)
			throw new SerializeException("The endpoint URI is not specified");
		
		HTTPRequest httpRequest;

		URL endpointURL;

		try {
			endpointURL = getEndpointURI().toURL();

		} catch (MalformedURLException e) {

			throw new SerializeException(e.getMessage(), e);
		}
		
		if (method.equals(HTTPRequest.Method.GET)) {

			httpRequest = new HTTPRequest(HTTPRequest.Method.GET, endpointURL);

		} else if (method.equals(HTTPRequest.Method.POST)) {

			httpRequest = new HTTPRequest(HTTPRequest.Method.POST, endpointURL);

		} else {

			throw new IllegalArgumentException("The HTTP request method must be GET or POST");
		}
		
		httpRequest.setQuery(toQueryString());
		
		return httpRequest;
	}
	
	
	@Override
	public HTTPRequest toHTTPRequest() {
	
		return toHTTPRequest(HTTPRequest.Method.GET);
	}


	/**
	 * Parses an authorisation request from the specified parameters.
	 *
	 * <p>Example parameters:
	 *
	 * <pre>
	 * response_type = code
	 * client_id     = s6BhdRkqt3
	 * state         = xyz
	 * redirect_uri  = https://client.example.com/cb
	 * </pre>
	 *
	 * @param params The parameters. Must not be {@code null}.
	 *
	 * @return The authorisation request.
	 *
	 * @throws ParseException If the parameters couldn't be parsed to an
	 *                        authorisation request.
	 */
	public static AuthorizationRequest parse(final Map<String,String> params)
		throws ParseException {

		return parse(null, params);
	}


	/**
	 * Parses an authorisation request from the specified parameters.
	 *
	 * <p>Example parameters:
	 *
	 * <pre>
	 * response_type = code
	 * client_id     = s6BhdRkqt3
	 * state         = xyz
	 * redirect_uri  = https://client.example.com/cb
	 * </pre>
	 *
	 * @param uri    The URI of the authorisation endpoint. May be
	 *               {@code null} if the {@link #toHTTPRequest()} method
	 *               will not be used.
	 * @param params The parameters. Must not be {@code null}.
	 *
	 * @return The authorisation request.
	 *
	 * @throws ParseException If the parameters couldn't be parsed to an
	 *                        authorisation request.
	 */
	public static AuthorizationRequest parse(final URI uri, final Map<String,String> params)
		throws ParseException {

		// Parse mandatory client ID first
		String v = params.get("client_id");

		if (StringUtils.isBlank(v)) {
			String msg = "Missing \"client_id\" parameter";
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
		}

		ClientID clientID = new ClientID(v);


		// Parse optional redirection URI second
		v = params.get("redirect_uri");

		URI redirectURI = null;

		if (StringUtils.isNotBlank(v)) {

			try {
				redirectURI = new URI(v);

			} catch (URISyntaxException e) {
				String msg = "Invalid \"redirect_uri\" parameter: " + e.getMessage();
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
					                 clientID, null, null, null, e);
			}
		}


		// Parse optional state third
		State state = State.parse(params.get("state"));


		// Parse mandatory response type
		v = params.get("response_type");

		ResponseType rt;

		try {
			rt = ResponseType.parse(v);

		} catch (ParseException e) {
			// Only cause
			String msg = "Missing \"response_type\" parameter";
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
				                 clientID, redirectURI, null, state, e);
		}


		// Parse the optional response mode
		v = params.get("response_mode");

		ResponseMode rm = null;

		if (StringUtils.isNotBlank(v)) {
			rm = new ResponseMode(v);
		}


		// Parse optional scope
		v = params.get("scope");

		Scope scope = null;

		if (StringUtils.isNotBlank(v))
			scope = Scope.parse(v);


		// Parse optional code challenge and method for PKCE
		CodeChallenge codeChallenge = null;
		CodeChallengeMethod codeChallengeMethod = null;

		v = params.get("code_challenge");

		if (StringUtils.isNotBlank(v))
			codeChallenge = new CodeChallenge(v);

		if (codeChallenge != null) {

			v = params.get("code_challenge_method");

			if (StringUtils.isNotBlank(v))
				codeChallengeMethod = CodeChallengeMethod.parse(v);
		}

		// Parse additional custom parameters
		Map<String,String> customParams = null;

		for (Map.Entry<String,String> p: params.entrySet()) {

			if (! REGISTERED_PARAMETER_NAMES.contains(p.getKey())) {
				// We have a custom parameter
				if (customParams == null) {
					customParams = new HashMap<>();
				}
				customParams.put(p.getKey(), p.getValue());
			}
		}


		return new AuthorizationRequest(uri, rt, rm, clientID, redirectURI, scope, state, codeChallenge, codeChallengeMethod, customParams);
	}


	/**
	 * Parses an authorisation request from the specified URI query string.
	 *
	 * <p>Example URI query string:
	 *
	 * <pre>
	 * response_type=code
	 * &amp;client_id=s6BhdRkqt3
	 * &amp;state=xyz
	 * &amp;redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
	 * </pre>
	 *
	 * @param query The URI query string. Must not be {@code null}.
	 *
	 * @return The authorisation request.
	 *
	 * @throws ParseException If the query string couldn't be parsed to an
	 *                        authorisation request.
	 */
	public static AuthorizationRequest parse(final String query)
		throws ParseException {

		return parse(null, URLUtils.parseParameters(query));
	}
	
	
	/**
	 * Parses an authorisation request from the specified URI query string.
	 *
	 * <p>Example URI query string:
	 *
	 * <pre>
	 * response_type=code
	 * &amp;client_id=s6BhdRkqt3
	 * &amp;state=xyz
	 * &amp;redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
	 * </pre>
	 *
	 * @param uri   The URI of the authorisation endpoint. May be 
	 *              {@code null} if the {@link #toHTTPRequest()} method
	 *              will not be used.
	 * @param query The URI query string. Must not be {@code null}.
	 *
	 * @return The authorisation request.
	 *
	 * @throws ParseException If the query string couldn't be parsed to an 
	 *                        authorisation request.
	 */
	public static AuthorizationRequest parse(final URI uri, final String query)
		throws ParseException {
	
		return parse(uri, URLUtils.parseParameters(query));
	}


	/**
	 * Parses an authorisation request from the specified URI.
	 *
	 * <p>Example URI:
	 *
	 * <pre>
	 * https://server.example.com/authorize?
	 * response_type=code
	 * &amp;client_id=s6BhdRkqt3
	 * &amp;state=xyz
	 * &amp;redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
	 * </pre>
	 *
	 * @param uri The URI. Must not be {@code null}.
	 *
	 * @return The authorisation request.
	 *
	 * @throws ParseException If the URI couldn't be parsed to an
	 *                        authorisation request.
	 */
	public static AuthorizationRequest parse(final URI uri)
		throws ParseException {

		return parse(URIUtils.getBaseURI(uri), URLUtils.parseParameters(uri.getRawQuery()));
	}
	
	
	/**
	 * Parses an authorisation request from the specified HTTP request.
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
			throw new ParseException("Missing URI query string");

		try {
			return parse(URIUtils.getBaseURI(httpRequest.getURL().toURI()), query);

		} catch (URISyntaxException e) {

			throw new ParseException(e.getMessage(), e);
		}
	}
}

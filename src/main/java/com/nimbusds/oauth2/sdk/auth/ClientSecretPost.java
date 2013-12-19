package com.nimbusds.oauth2.sdk.auth;


import java.util.HashMap;
import java.util.Map;

import javax.mail.internet.ContentType;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * Client secret post authentication at the Token endpoint. Implements
 * {@link ClientAuthenticationMethod#CLIENT_SECRET_POST}.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 2.3.1.
 * </ul>
 */
@Immutable
public final class ClientSecretPost extends ClientAuthentication {


	/**
	 * The client secret.
	 */
	private final Secret secret;
	
	
	/**
	 * Creates a new client secret post authentication.
	 *
	 * @param clientID The client identifier. Must not be {@code null}.
	 * @param secret   The client secret. Must not be {@code null}.
	 */
	public ClientSecretPost(final ClientID clientID, final Secret secret) {
	
		super(ClientAuthenticationMethod.CLIENT_SECRET_POST, clientID);
	
		if (secret == null)
			throw new IllegalArgumentException("The client secret must not be null");
		
		this.secret = secret;
	}
	
	
	/**
	 * Gets the client secret.
	 *
	 * @return The client secret.
	 */
	public Secret getClientSecret() {
	
		return secret;
	}
	
	
	/**
	 * Returns the parameter representation of this client secret post
	 * authentication. Note that the parameters are not 
	 * {@code application/x-www-form-urlencoded} encoded.
	 *
	 * <p>Parameters map:
	 *
	 * <pre>
	 * "client_id" -> [client-identifier]
	 * "client_secret" -> [client-secret]
	 * </pre>
	 *
	 * @return The parameters map, with keys "client_id" and 
	 *         "client_secret".
	 */
	public Map<String,String> toParameters() {
	
		Map<String,String> params = new HashMap<String,String>();
		
		params.put("client_id", getClientID().getValue());
		params.put("client_secret", secret.getValue());
		
		return params;
	}
	
	
	@Override
	public void applyTo(final HTTPRequest httpRequest)
		throws SerializeException {
	
		if (httpRequest.getMethod() != HTTPRequest.Method.POST)
			throw new SerializeException("The HTTP request method must be POST");
		
		ContentType ct = httpRequest.getContentType();
		
		if (ct == null)
			throw new SerializeException("Missing HTTP Content-Type header");
		
		if (! ct.match(CommonContentTypes.APPLICATION_URLENCODED))
			throw new SerializeException("The HTTP Content-Type header must be " + CommonContentTypes.APPLICATION_URLENCODED);
		
		Map <String,String> params = httpRequest.getQueryParameters();
		
		params.putAll(toParameters());
		
		String queryString = URLUtils.serializeParameters(params);
		
		httpRequest.setQuery(queryString);
	}
	
	
	/**
	 * Parses a client secret post authentication from the specified 
	 * parameters map. Note that the parameters must not be
	 * {@code application/x-www-form-urlencoded} encoded.
	 *
	 * @param params The parameters map to parse. The client secret post
	 *               parameters must be keyed under "client_id" and 
	 *               "client_secret". The map must not be {@code null}.
	 *
	 * @return The client secret post authentication.
	 *
	 * @throws ParseException If the parameters map couldn't be parsed to a 
	 *                        client secret post authentication.
	 */
	public static ClientSecretPost parse(final Map<String,String> params)
		throws ParseException {
	
		String clientIDString = params.get("client_id");
		
		if (clientIDString == null)
			throw new ParseException("Missing \"client_id\" parameter");
		
		String secretValue = params.get("client_secret");
		
		if (secretValue == null)
			throw new ParseException("Missing \"client_secret\" parameter");
		
		return new ClientSecretPost(new ClientID(clientIDString), new Secret(secretValue));
	}
	
	
	/**
	 * Parses a client secret post authentication from the specified 
	 * {@code application/x-www-form-urlencoded} encoded parameters string.
	 *
	 * @param paramsString The parameters string to parse. The client secret
	 *                     post parameters must be keyed under "client_id" 
	 *                     and "client_secret". The string must not be 
	 *                     {@code null}.
	 *
	 * @return The client secret post authentication.
	 *
	 * @throws ParseException If the parameters string couldn't be parsed to
	 *                        a client secret post authentication.
	 */
	public static ClientSecretPost parse(final String paramsString)
		throws ParseException {
		
		Map<String,String> params = URLUtils.parseParameters(paramsString);
		
		return parse(params);
	}
	
	
	/**
	 * Parses a client secret post authentication from the specified HTTP
	 * POST request.
	 *
	 * @param httpRequest The HTTP POST request to parse. Must not be 
	 *                    {@code null} and must contain a valid 
	 *                    {@code application/x-www-form-urlencoded} encoded 
	 *                    parameters string in the entity body. The client 
	 *                    secret post parameters must be keyed under 
	 *                    "client_id" and "client_secret".
	 *
	 * @return The client secret post authentication.
	 *
	 * @throws ParseException If the HTTP request header couldn't be parsed
	 *                        to a valid client secret post authentication.
	 */
	public static ClientSecretPost parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		httpRequest.ensureMethod(HTTPRequest.Method.POST);
		httpRequest.ensureContentType(CommonContentTypes.APPLICATION_URLENCODED);
		
		return parse(httpRequest.getQueryParameters());
	}
}

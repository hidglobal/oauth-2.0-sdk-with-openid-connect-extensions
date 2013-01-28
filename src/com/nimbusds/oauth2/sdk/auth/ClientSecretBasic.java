package com.nimbusds.oauth2.sdk.auth;


import java.io.UnsupportedEncodingException;

import net.jcip.annotations.Immutable;

import org.apache.commons.codec.binary.Base64;

import com.nimbusds.oauth2.sdk.ParseException;

import com.nimbusds.oauth2.sdk.id.ClientID;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;


/**
 * Client secret basic authentication at the Token endpoint. Implements
 * {@link ClientAuthenticationMethod#CLIENT_SECRET_BASIC}. This class is
 * immutable.
 *
 * <p>Example HTTP Authorization header (for client identifier "Aladdin" and
 * password "open sesame"):
 *
 * <pre>
 * Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 2.3.1.
 *     <li>HTTP Authentication: Basic and Digest Access Authentication 
 *         (RFC 2617).
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-28)
 */
@Immutable
public final class ClientSecretBasic extends ClientAuthentication {


	/**
	 * The client ID.
	 */
	private final ClientID clientID;
	
	
	/**
	 * The client secret.
	 */
	private final Secret secret;
	
	
	/**
	 * Creates a new client secret basic authentication.
	 *
	 * @param clientID The client identifier. Must not be {@code null}.
	 * @param secret   The client secret. Must not be {@code null}.
	 */
	public ClientSecretBasic(final ClientID clientID, final Secret secret) {
	
		super(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
	
		if (clientID == null)
			throw new IllegalArgumentException("The client ID must not be null");
		
		this.clientID = clientID;
		
		if (secret == null)
			throw new IllegalArgumentException("The client secret must not be null");
		
		this.secret = secret;
	}
	
	
	/**
	 * Gets the client identifier.
	 *
	 * @return The client identifier.
	 */
	public ClientID getClientID() {
	
		return clientID;
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
	 * Returns the HTTP Authorization header representation of this client
	 * secret basic authentication.
	 *
	 * <p>Example HTTP Authorization header (for client identifier "Aladdin"
	 * and password "open sesame"):
	 *
	 * <pre>
	 * Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
	 * </pre>
	 *
	 * <p>See RFC 2617, section 2.
	 *
	 * @return The HTTP Authorization header.
	 */
	public String toHTTPAuthorizationHeader() {
	
		StringBuilder sb = new StringBuilder(clientID.toString());
		sb.append(':');
		sb.append(secret.getValue());
		
		String b64 = null;
		
		try {
			b64 = Base64.encodeBase64String(sb.toString().getBytes("utf-8"));
			
		} catch (UnsupportedEncodingException e) {
		
			// UTF-8 should always be supported
		}
		
		return "Basic " + b64;
	}
	
	
	@Override
	public void apply(final HTTPRequest httpRequest) {
	
		httpRequest.setAuthorization(toHTTPAuthorizationHeader());
	}
	
	
	/**
	 * Parses a client secret basic authentication from the specified HTTP
	 * Authorization header.
	 *
	 * @param header The HTTP Authorization header to parse. Must not be 
	 *               {@code null}.
	 *
	 * @return The client secret basic authentication.
	 *
	 * @throws ParseException If the header couldn't be parsed to a client
	 *                        secret basic authentication.
	 */
	public static ClientSecretBasic parse(final String header)
		throws ParseException {
		
		String[] parts = header.split("\\s");
		
		if (parts.length != 2)
			throw new ParseException("Unexpected number of HTTP Authorization header value parts: " + parts.length);
		
		if (! parts[0].equalsIgnoreCase("Basic"))
			throw new ParseException("HTTP authentication must be \"Basic\"");
		
		
		String credentialsString = null;
		
		try {
			credentialsString = new String(Base64.decodeBase64(parts[1]), "utf-8");
			
		} catch (UnsupportedEncodingException e) {
		
			throw new ParseException(e.getMessage(), e);
		}
		
		String[] credentials = credentialsString.split(":", 2);
		
		if (credentials.length != 2)
			throw new ParseException("Missing credentials delimiter \":\"");
		
		ClientID clientID = new ClientID(credentials[0]);
		Secret secret = new Secret(credentials[1]);
		
		return new ClientSecretBasic(clientID, secret);
	}
	
	
	/**
	 * Parses a client secret basic authentication from the specified HTTP
	 * request.
	 *
	 * @param httpRequest The HTTP request to parse. Must not be 
	 *                    {@code null} and must contain a valid 
	 *                    Authorization header.
	 *
	 * @return The client secret basic authentication.
	 *
	 * @throws ParseException If the HTTP Authorization header couldn't be 
	 *                        parsed to a client secret basic 
	 *                        authentication.
	 */
	public static ClientSecretBasic parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		String header = httpRequest.getAuthorization();
		
		if (header == null)
			throw new ParseException("Missing HTTP Authorization header");
			
		return parse(header);
	}
}

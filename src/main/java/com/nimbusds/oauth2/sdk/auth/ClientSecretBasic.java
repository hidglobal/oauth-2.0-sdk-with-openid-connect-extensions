package com.nimbusds.oauth2.sdk.auth;


import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;

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
 * <p>Example HTTP Authorization header (for client identifier "s6BhdRkqt3" and
 * secret "7Fjfp0ZBr1KtDRbnfVdmIw"):
 *
 * <pre>
 * Authorization: Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3
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
		
		String b64 = null;
		
		try {
			String encodedClientID = URLEncoder.encode(clientID.toString(), "UTF-8");
			String encodedSecret = URLEncoder.encode(secret.getValue(), "UTF-8");

			StringBuilder sb = new StringBuilder(encodedClientID);
			sb.append(':');
			sb.append(encodedSecret);

			b64 = Base64.encodeBase64String(sb.toString().getBytes("UTF-8"));
			
		} catch (UnsupportedEncodingException e) {
		
			// UTF-8 should always be supported
		}
		
		return "Basic " + b64;
	}
	
	
	@Override
	public void applyTo(final HTTPRequest httpRequest) {
	
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
		
		try {
			String credentialsString = new String(Base64.decodeBase64(parts[1]), "utf-8");

			String[] credentials = credentialsString.split(":", 2);
		
			if (credentials.length != 2)
				throw new ParseException("Missing credentials delimiter \":\"");

			String decodedClientID = URLDecoder.decode(credentials[0], "utf-8");
			String decodedSecret = URLDecoder.decode(credentials[1], "utf-8");

			return new ClientSecretBasic(new ClientID(decodedClientID), new Secret(decodedSecret));
			
		} catch (UnsupportedEncodingException e) {
		
			throw new ParseException(e.getMessage(), e);
		}
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

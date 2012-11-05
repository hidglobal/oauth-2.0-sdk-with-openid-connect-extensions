package com.nimbusds.openid.connect.sdk.messages;


/**
 * Client authentication method at the Token endpoint.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.2.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-11-05)
 */
public class ClientAuthenticationMethod {


	/**
	 * Clients that have received a {@code client_secret} value from the 
	 * authorisation server, authenticate with the authorisation server in 
	 * accordance with section 3.2.1 of OAuth 2.0 using HTTP Basic 
	 * authentication scheme. This is the default if no method has been
	 * registered for the client.
	 */
	public static final ClientAuthenticationMethod CLIENT_SECRET_BASIC = 
		new ClientAuthenticationMethod("client_secret_basic");


	/**
	 * Clients that have received a {@code client_secret} value from the 
	 * authorisation server, authenticate with the authorisation server in 
	 * accordance with section 3.2.1 of OAuth 2.0 by including the client 
	 * credentials in the request body.
	 */
	public static final ClientAuthenticationMethod CLIENT_SECRET_POST =
		new ClientAuthenticationMethod("client_secret_post");


	/**
	 * Clients that have received a {@code client_secret} value from the 
	 * authorisation server, create a JWT using an HMAC SHA algorithm, such 
	 * as HMAC SHA-256. The HMAC (Hash-based Message Authentication Code) is
	 * calculated using the value of {@code client_secret} as the shared 
	 * key. The client authenticates in accordance with section 2.2 of (JWT) 
	 * Bearer Token Profiles and OAuth 2.0 Assertion Profile. 
	 */
	public static final ClientAuthenticationMethod CLIENT_SECRET_JWT =
		new ClientAuthenticationMethod("client_secret_jwt");


	/**
	 * Clients that have registered a public key sign a JWT using the RSA 
	 * algorithm if a RSA key was registered or the ECDSA algorithm if an 
	 * Elliptic Curve key was registered (see JWA for the algorithm 
	 * identifiers). The client authenticates in accordance with section 2.2
	 * of (JWT) Bearer Token Profiles and OAuth 2.0 Assertion Profile.
	 */
	public static final ClientAuthenticationMethod PRIVATE_KEY_JWT =
		new ClientAuthenticationMethod("private_key_jwt");


	/**
	 * Gets the default client authentication method.
	 */
	public static ClientAuthenticationMethod getDefault() {

		return CLIENT_SECRET_BASIC;
	}


	/**
	 * The method name.
	 */
	private String name;


	/**
	 * Creates a new client authentication method.
	 *
	 * @param name The method name. Must not be {@code null}.
	 */
	public ClientAuthenticationMethod(final String name) {

		if (name == null)
			throw new IllegalArgumentException("The method name must not be null");

		this.name = name;
	}


	/**
	 * Gets the name of the client authentication method.
	 *
	 * @return The method name.
	 */
	public String getName() {

		return name;
	}


	/**
	 * @see #getName
	 */
	@Override
	public String toString() {

		return name;
	}


	/**
	 * Returns a hash code based on the method name.
	 *
	 * @return Hash code based on the method name.
	 */
	@Override
	public int hashCode() {

		return name.hashCode();
	}


	/**
	 * Overrides {@code Object.equals()}.
	 *
	 * @param object The object to compare to.
	 *
	 * @return {@code true} if the two objects are client authentication
	 *         methods with the same name, otherwise {@code false}.
	 */
	@Override
	public boolean equals(final Object object) {

		return object != null &&
		       object instanceof ClientAuthenticationMethod &&
		       this.getName().equals(((ClientAuthenticationMethod)object).getName());
	}
}
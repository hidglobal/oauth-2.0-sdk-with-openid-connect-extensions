package com.nimbusds.openid.connect.messages;


/**
 * Test vectors, including official from the OpenID Connect specification.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-24)
 */
public class TestVectors {


	/**
	 * Authorisation requests.
	 */
	public static final class AuthorizationRequest {

		/**
		 * Simple request method.
		 *
		 * <p>See OpenID Connect Standard 1.0, section 2.3.1.1
		 */
		public static final String SIMPLE_REQUEST =

			"response_type=code%20id_token" +
			"&client_id=s6BhdRkqt3" +
			"&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
			"&scope=openid" +
			"&nonce=n-0S6_WzA2Mj" +
			"&state=af0ifjsldkj";


		}
	


}
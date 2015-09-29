package com.nimbusds.oauth2.sdk.auth.verifiers;


import java.security.Key;
import java.util.List;
import java.util.Set;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.JWTAuthentication;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import net.jcip.annotations.ThreadSafe;


/**
 * Client authentication verifier. Before it can be used it must be
 * provided with a {@link com.nimbusds.jose.proc.JWSKeySelector} to lookup the
 * client keys for the JWT authentication assertions.
 */
@ThreadSafe
public class ClientAuthenticationVerifier<T> {


	/**
	 * The expected audience.
	 */
	private final Set<Audience> expectedAudience;


	private final DefaultJWTProcessor<ClientAuthenticationContext<T>> jwtProcessor;


	private final ClientCredentialsSelector<T> clientCredentialsSelector;


	public ClientAuthenticationVerifier(final Set<Audience> expectedAudience,
					    final ClientCredentialsSelector<T> clientCredentialsSelector) {

		if (expectedAudience == null || expectedAudience.isEmpty()) {
			throw new IllegalArgumentException("The expected audience set must not be null or empty");
		}

		this.expectedAudience = expectedAudience;


		this.clientCredentialsSelector = clientCredentialsSelector;

		this.jwtProcessor = new DefaultJWTProcessor<>();

		this.jwtProcessor.setJWSKeySelector(clientCredentialsSelector);
	}


	public T verify(final ClientAuthentication clientAuth)
		throws InvalidClientException {

		ClientAuthenticationContext<T> ctx = new ClientAuthenticationContext<>(clientAuth);


		if (clientAuth instanceof JWTAuthentication) {

			JWTAuthentication jwtAuth = (JWTAuthentication)clientAuth;

			try {
				jwtProcessor.process(jwtAuth.getClientAssertion(), ctx);

			} catch (BadJOSEException e) {
				throw new InvalidClientException(e.getMessage());
			} catch (JOSEException e) {
				throw new RuntimeException(e.getMessage(), e);
			}
		}

		return ctx.getData();
	}
}

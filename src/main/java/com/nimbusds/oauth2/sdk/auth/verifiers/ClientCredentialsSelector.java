package com.nimbusds.oauth2.sdk.auth.verifiers;


import java.util.List;

import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.oauth2.sdk.auth.Secret;


/**
 * Client credentials selector
 */
public interface ClientCredentialsSelector<T> extends JWSKeySelector<ClientAuthenticationContext<T>>{



	List<Secret> selectClientSecrets(final ClientAuthenticationContext<T> context);
}

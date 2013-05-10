import java.net.*;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.id.*;
import com.nimbusds.openid.connect.sdk.*;


/**
 * Demonstrates the construction of an OIDC authorisation request.
 *
 * @author Vladimir Dzhuvinov
 * @version 2013-05-09
 */
public class ClientAuthzStep {


	public static void main(final String[] args)
		throws Exception {

		// Set the requested response_type (code, token and / or 
		// id_token):
		// Use CODE for authorisation code flow
		// Use TOKEN for implicit flow
		ResponseTypeSet rts = new ResponseTypeSet();
		rts.add(ResponseType.CODE);

		// Set the requested scope of access
		Scope scope = new Scope();
		scope.add(OIDCScopeToken.OPENID);
		scope.add(OIDCScopeToken.EMAIL);
		scope.add(OIDCScopeToken.PROFILE);

		// Identify the client app by its registered ID
		ClientID clientID = new ClientID("0ddce2239c2b075732c989fc0b69d86e");

		// Set the redirect URL after successful OIDC login / 
		// authorisation. This URL is typically registered in advance 
		// with the OIDC server
		URL redirectURI = new URL("https://oidc-test-client.nimbusds.com/in");

		// Generate nonce with 8 random characters. It's used to link 
		// the authorisation response back to the original request, 
		// also to prevent replay attacks
		Nonce nonce = new Nonce(8);


		// Create the actual OIDC authorisation request object
		OIDCAuthorizationRequest authzReq = new OIDCAuthorizationRequest(rts, scope, clientID, redirectURI, nonce);


		// Get the resulting URL query string with the authorisation
		// request encoded into it
		String queryString = authzReq.toQueryString();


		// Set the base URL of the OIDC server authorisation endpoint
		URL authzEndpointURL = new URL("https://www.paypal.com/webapps/auth/protocol/openidconnect/v1/authorize");


		// Construct and output the final OIDC authorisation URL for
		// redirect
		URL authzURL = new URL(authzEndpointURL + "?" + queryString);


		// Redirect the user to the URL below for OIDC login /
		// authorisation, then get the response at the redirectURI 
		// set above
		System.out.println(authzURL);
	}
}
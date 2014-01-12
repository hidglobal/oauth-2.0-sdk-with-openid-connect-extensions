Nimbus OAuth 2.0 SDK with OpenID Connect extensions

Copyright (c) Nimbus Directory Services, 2012 - 2014


README

This open source Java library is your starting point for developing OAuth 2.0
and OpenID Connect based applications:

	* Developing OAuth 2.0 servers:

		- Parse and process requests at the Authorisation Endpoint, 
		  then generate the appropriate responses with an authorisation
		  code or access token;

		- Parse and process requests at the Token Endpoint, then 
		  generate the appropriate responses.

	* Developing OAuth 2.0 clients:

		- Compose requests to an OAuth 2.0 Authorisation Endpoint and
		  parse the responses;

		- Compose requests to an OAuth 2.0 Token Endpoint and parse the
		  responses;

		- Make requests to a protected resource using an OAuth 2.0
		  access token.

	* Developing OpenID Connect provider (OP) servers:
	
		- Parse and process requests at the OpenID Connect 
		  Authorisation Endpoint, then generate the appropriate 
		  responses with an authorisation code, ID Token and / or
		  UserInfo access token;
		  
		- Parse and process requests at the OpenID Connect Token 
		  Endpoint, then generate the appropriate responses;
		  
		- Parse and process requests at the OpenID Connect UserInfo 
		  Endpoint, then generate the appropriate responses;
		  
		- Parse and process requests at the OpenID Connect Client
		  Registration endpoint, then generate the appropriate 
		  responses.
	
	* Developing OpenID Connect relying party (RP) clients:
	
		- Compose requests to an OpenID Connect Authorisation Endpoint
		  and parse the responses;
		  
		- Compose requests to an OpenID Connect Token Endpoint and
		  parse the responses;
		  
		- Compose requests to an OpenID Connect UserInfo Endpoint and
		  parse the responses;
		  
		- Compose requests to an OpenID Connect Client Registration
		  Endpoint and parse the responses.


Additional features:

	* Process plain, signed and encrypted JSON Web Tokens (JWTs) with help 
	  of the Nimbus JOSE+JWT library.

	* Full OpenID Connect UserInfo i10n and l10n support with help of the
	  Nimbus Language Tags (RFC 5646) library.


This SDK version implements the following standards and drafts:


	* The OAuth 2.0 Authorization Framework (RFC 6749)

	* The OAuth 2.0 Authorization Framework: Bearer Token Usage (RFC 6750)
	
	* OAuth 2.0 Dynamic Client Registration Protocol 
	  (draft-ietf-oauth-dyn-reg-14)

	* OpenID Connect Core, draft 17.

	* OpenID Connect Discovery, draft 21.

	* OpenID Connect Registration, draft 23.

	* OAuth 2.0 Multiple Response Type Encoding Practices, draft 11.


The Nimbus OAuth 2.0 + OpenID Connect SDK is provided under the terms of the
Apache 2.0 licence.


2014-01-12

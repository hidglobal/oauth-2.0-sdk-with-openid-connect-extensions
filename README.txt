Nimbus OpenID Connect SDK

Copyright (c) Nimbus Directory Services / Vladimir Dzhuvinov, 2012


README

The Nimbus OpenID Connect SDK for Java is your starting point for:

	* Developing Identity Provider (IdP) servers based on OpenID Connect:
	
		- Parse and process requests at the OpenID Connect Authorisation
		  Endpoint, then generate the appropriate responses with an ID 
		  Token, UserInfo access token and/or authorisation code;
		  
		- Parse and process requests at the OpenID Connect Token 
		  Endpoint, then generate the appropriate responses;
		  
		- Parse and process requests at the OpenID Connect UserInfo 
		  Endpoint, then generate the appropriate responses.
	
	* Developing OpenID Connect clients in Java:
	
		- Compose requests to an OpenID Connect Authorization Endpoint
		  and parse the responses;
		  
		- Compose requests to an OpenID Connect Token Endpoint and
		  parse the responses;
		  
		- Compose requests to an OpenID Connect UserInfo Endpoint and
		  parse the responses.


Additional features:

	* Process plain, signed and encrypted JSON Web Tokens (JWTs) through the
	  Nimbus-JWT library.

	* Full UserInfo i10n support through the Nimbus Language Tags (RFC 5646)
	  library.



This SDK version implements the OpenID Connect draft suite from 10 April 2012.


The SDK JavaDocs are at http://nimbusds.com/files/openid-connect-sdk/javadoc/


The Nimbus OpenID Connect SDK is licensed under GPL 2.0. Licences for 
integration into commercial products and services are available for a small fee,
please get in touch with us at http://nimbusds.com/contact.html


2012-05-29

[eof]

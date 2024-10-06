spring-authorization-server

- refer to .http file in doc to test api.
- use 'redis' profile to activate redis implementation.


- this is redis implementation of spring authorization server.
- spring resource server implementation is here : https://github.com/loonabus/spring-resource-server.git
- redis implementation of RegisteredClientRepository & OAuth2AuthorizationService on my own.
- custom grant type included similar to 'password' grant type.
- I referred to built in implementation classes such as 'OAuth2AuthorizationCodeAuthenticationProvider' and several classes to write codes for custom grant type and redis implementation. : most classes are 'final' so copy-and-paste and recreated with my own.
- use your own rsa key pair for security.


- I made this on July 2024 with version 1.3.1 and uploaded on October 2024 for archive.
- and I found below document on spring.io. check this reference document.
- https://docs.spring.io/spring-authorization-server/reference/1.4/guides/how-to-redis.html
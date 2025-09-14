package northwind.config;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.*;

import org.apache.commons.collections4.CollectionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import northwind.filter.AfterX509AuthenticationFilter;
import northwind.jwk.JsonWebTokenKeySet;
import northwind.oauth.converter.X509ClientCertificateAuthenticationConverter;
import northwind.oauth.provider.X509ClientCertificateAuthenticationProvider;
import northwind.util.SslUtil;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
//@Import(OAuth2AuthorizationServerConfiguration.class)
@ComponentScan(basePackages= {"northwind"})
public class AuthServerConfig {
	
	@Autowired
	private JsonWebTokenKeySet jwtKeySet;
	
	@Bean 
	@Order(1)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,JWKSet jwkSet)
			throws Exception {
		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
				OAuth2AuthorizationServerConfigurer.authorizationServer();
		authorizationServerConfigurer
		.clientAuthentication(clientAuthentication ->
			clientAuthentication
				.authenticationConverter(
					new X509ClientCertificateAuthenticationConverter())
				.authenticationProvider(
					new X509ClientCertificateAuthenticationProvider(registeredClientRepository()))
		);

		RequestMatcher endpointsMatcher = authorizationServerConfigurer
				.getEndpointsMatcher();

		http
				//.securityMatcher("/oauth2/**", "/.well-known/**")
				.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
				.with(authorizationServerConfigurer, (authorizationServer) ->
						authorizationServer
								.oidc(Customizer.withDefaults())	// Enable OpenID Connect 1.0
				)
				.authorizeHttpRequests(authorize -> authorize
						.requestMatchers("/oauth2/token", "/oauth2/authorize", "/oauth2/introspect",
								"/oauth2/revoke", "/.well-known/**")
						.permitAll()
						.anyRequest().authenticated()
				)
				.csrf(csrf -> csrf.ignoringRequestMatchers(
						new OrRequestMatcher(
								PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, "/oauth2/token"),
								PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.GET, "/oauth2/authorize"),
								PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, "/oauth2/introspect"),
								PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, "/oauth2/revoke"),
								PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.GET, "/.well-known/**")
						)
				));
		http
		.x509()
		.subjectPrincipalRegex("CN=(.*?)(?:,|$)")
        .userDetailsService(userDetailsService());

        http.addFilterAfter(new AfterX509AuthenticationFilter(), X509AuthenticationFilter.class);
		return http.formLogin(Customizer.withDefaults()).build();
	}



	
    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) {
                if (username.equals("mtls-client")) {
                    return new User(username, "", 
                      AuthorityUtils
                        .commaSeparatedStringToAuthorityList("ROLE_USER"));
                }
                throw new UsernameNotFoundException("User not found!");
            }
        };
    }

	@Bean
	public OAuth2AuthorizationService authorizationService() {
		return new InMemoryOAuth2AuthorizationService();
	}
	
	@Bean
	public JwtGenerator tokenGenerator(JWKSet jwkSet) {
		JWKSource<SecurityContext> jwkSource = jwkSource(jwkSet);
		JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
		JwtGenerator tokenGenerator =  new JwtGenerator(jwtEncoder);
		tokenGenerator.setJwtCustomizer(jwtCustomizer(jwkSet));
		return tokenGenerator;
	}
	
	@Bean 
	public RegisteredClientRepository registeredClientRepository() {
		RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("mtls-client")
				//{noop} refers to NoOpPasswordEncoder 
				.clientSecret("{noop}password")
				.clientAuthenticationMethod(new ClientAuthenticationMethod("tls_client_auth"))
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
				.redirectUri("http://127.0.0.1:8080/authorized")
				.scope(OidcScopes.OPENID)
				.scope("product.read")
				.scope("product.write")
				.clientSettings(ClientSettings.builder()
							.requireAuthorizationConsent(false)
							.requireProofKey(true)
							.setting("SubjectDN", "CN=mtls-client, OU=SuccessFactors, O=SAP, L=Bangalore, ST=Karnataka, C=IN")
							.build())
				.tokenSettings(TokenSettings.builder()
				.accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
			    .accessTokenTimeToLive(Duration.ofMinutes(30L))
				.build())

				.build();

		return new InMemoryRegisteredClientRepository(registeredClient);
	}

	@Bean 
	public JWKSource<SecurityContext> jwkSource(JWKSet jwkSet) {
		return new ImmutableJWKSet<>(jwkSet);
	}
	
	@Bean 
	public JWKSet jwkSet() {
		JWKSet jwkSet = new JWKSet(jwtKeySet.generateRsa());
		return jwkSet;
	}

	@Bean
	public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer(JWKSet jwkSet) {
		return context -> {
			if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
				OAuth2ClientAuthenticationToken clientAuthentication =
						(OAuth2ClientAuthenticationToken) context.getAuthorizationGrant().getPrincipal();
				X509Certificate x509Certificate = (X509Certificate) clientAuthentication.getCredentials();
				String sha256Thumbprint = SslUtil.computeThumbprint(x509Certificate);
				Optional<JWK> jwkOptional = jwkSet.getKeys().stream().findAny();

				Set<String> scopes = context.getAuthorizedScopes();

				// If authorized scopes is empty, try to get from the OAuth2TokenContext
				if (CollectionUtils.isEmpty(scopes)) {
					// Get scopes from the token request context
					OAuth2Authorization authorization = context.get(OAuth2Authorization.class);
					if (authorization != null) {
						scopes = authorization.getAuthorizedScopes();
					}
				}

				if (CollectionUtils.isEmpty(scopes)) {
					RegisteredClient registeredClient = context.get(RegisteredClient.class);
					if (registeredClient != null) {
						// For client_credentials grant, use all client scopes
						scopes = registeredClient.getScopes();
					}
				}

				if (!CollectionUtils.isEmpty(scopes)) {
					List<String> scopesList = new ArrayList<>(scopes);
					context.getClaims().claim("scope", scopesList);
					context.getClaims().claim("scp", String.join(" ", scopes));
				}

				if (sha256Thumbprint != null) {
					context.getClaims().claim("x5tc#S256", sha256Thumbprint);
					//context.getHeaders().x509SHA256Thumbprint(sha256Thumbprint);
					context.getJwsHeader().algorithm(SignatureAlgorithm.RS256);
					jwkOptional.ifPresent(jwt -> context.getJwsHeader().keyId(jwt.getKeyID()));
					
					//context.getHeaders().x509CertificateChain(List.of(x509Certificate.getPublicKey().getFormat()));
				}
			}
		};
	}


}

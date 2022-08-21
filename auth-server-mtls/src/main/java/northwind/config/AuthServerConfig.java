package northwind.config;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2TokenFormat;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import northwind.filter.AfterX509AuthenticationFilter;
import northwind.jwk.JsonWebTokenKeySet;
import northwind.oauth.converter.ResourceValidatingAuthenticationConverter;
import northwind.oauth.converter.X509ClientCertificateAuthenticationConverter;
import northwind.oauth.provider.X509ClientCertificateAuthenticationProvider;
import northwind.oauth.provider.X509ClientCredentialAuthenticationProvider;
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
		OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
				new OAuth2AuthorizationServerConfigurer<>();
		authorizationServerConfigurer
		.clientAuthentication(clientAuthentication ->
			clientAuthentication
				.authenticationConverter(
					new X509ClientCertificateAuthenticationConverter())
				.authenticationProvider(
					new X509ClientCertificateAuthenticationProvider(registeredClientRepository()))
		)
		.tokenEndpoint(tokenEndpoint ->
			tokenEndpoint
				.accessTokenRequestConverter(
						new ResourceValidatingAuthenticationConverter())
				.authenticationProvider(new X509ClientCredentialAuthenticationProvider(registeredClientRepository(),
						authorizationService(),tokenGenerator(jwkSet)))
		);
		
		RequestMatcher endpointsMatcher = authorizationServerConfigurer
				.getEndpointsMatcher();

		http
			.requestMatcher(endpointsMatcher)
			.authorizeRequests(authorizeRequests ->
				authorizeRequests.anyRequest().authenticated()
			)
			.csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
			.apply(authorizationServerConfigurer);
		http
		.x509()
		.subjectPrincipalRegex("CN=(.*?)(?:,|$)")
        .userDetailsService(userDetailsService())
		.and()
		.csrf().disable();

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
				.clientId("client")
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
				
				if (sha256Thumbprint != null) {
					context.getClaims().claim("x5tc#S256", sha256Thumbprint);
					//context.getHeaders().x509SHA256Thumbprint(sha256Thumbprint);
					context.getHeaders().algorithm( SignatureAlgorithm.RS256 );
					jwkOptional.ifPresent(jwt -> context.getHeaders().keyId(jwt.getKeyID()));
					
					//context.getHeaders().x509CertificateChain(List.of(x509Certificate.getPublicKey().getFormat()));
				}
			}
		};
	}

	@Bean 
	public ProviderSettings providerSettings() {
		return ProviderSettings.builder().issuer("https://localhost:8443").build();
	}

}

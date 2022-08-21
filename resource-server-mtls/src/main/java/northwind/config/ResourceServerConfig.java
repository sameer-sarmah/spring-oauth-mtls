package northwind.config;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import javax.net.ssl.SSLContext;

import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.HttpClients;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.web.SecurityFilterChain;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.web.client.RestTemplate;

import northwind.authentication.X509ClientCertificateClaimValidator;
import northwind.filter.AfterX509AuthenticationFilter;

@Configuration
@EnableWebSecurity
@ComponentScan(basePackages= {"northwind"})
public class ResourceServerConfig {
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		
		http
		.x509()
		.subjectPrincipalRegex("CN=(.*?)(?:,|$)")
        .userDetailsService(userDetailsService())
		.and()
		.csrf().disable();

        http.addFilterAfter(new AfterX509AuthenticationFilter(), X509AuthenticationFilter.class);
		
		http
			.mvcMatcher("/products/**")
				.authorizeRequests()
					.mvcMatchers("/products/**").access("hasAuthority('SCOPE_product.read')")
					.and()
			.oauth2ResourceServer()
				.jwt();
		return http.build();
	}
	
	@Bean
	JwtDecoder jwtDecoder(@Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}") String jwkSetUri,
			RestTemplateBuilder builder, Supplier<ClientHttpRequestFactory> clientHttpRequestFactory) {

		RestTemplate restTemplate = builder
				.requestFactory(clientHttpRequestFactory)
				.build();

		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri)
				.restOperations(restTemplate)
				.build();

		List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
		validators.add(new JwtTimestampValidator());
		validators.add(new X509ClientCertificateClaimValidator());
		jwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(validators));

		return jwtDecoder;
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
	Supplier<ClientHttpRequestFactory> clientHttpRequestFactory(SSLContext sslContext) {
		return () -> {
			HttpClient client = HttpClients.custom()
					.setSSLContext(sslContext)
					.setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
					.build();
			return new HttpComponentsClientHttpRequestFactory(client);
		};
	}
}

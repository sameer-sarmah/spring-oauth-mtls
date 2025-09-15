package northwind.config;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;


import northwind.util.CertificateUtil;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.BasicHttpClientConnectionManager;
import org.apache.hc.client5.http.socket.ConnectionSocketFactory;
import org.apache.hc.client5.http.socket.PlainConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.EntityDetails;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.HttpResponseInterceptor;
import org.apache.hc.core5.http.config.Registry;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.http.protocol.HttpCoreContext;
import org.slf4j.Logger;
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

	@Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
	private String jwkSetUri;

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

		http
				.authorizeHttpRequests(authorize -> authorize
						.requestMatchers("/products/**")
						.hasAuthority("SCOPE_product.read")
						.anyRequest().authenticated()
				)
				.oauth2ResourceServer(oauth2 -> oauth2.jwt());

		http
		.x509()
		.subjectPrincipalRegex("CN=(.*?)(?:,|$)")
        .userDetailsService(userDetailsService())
		.and()
		.csrf().disable();

        http.addFilterAfter(new AfterX509AuthenticationFilter(), X509AuthenticationFilter.class);

		return http.build();
	}

	@Bean
	JwtDecoder jwtDecoder(RestTemplateBuilder builder, Supplier<ClientHttpRequestFactory> clientHttpRequestFactory) {

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
	CloseableHttpClient clientHttpClient(SSLContext sslContext) {
		SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslContext,
				NoopHostnameVerifier.INSTANCE);

		Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
				.register("https", sslsf)
				.register("http", new PlainConnectionSocketFactory())
				.build();

		HttpResponseInterceptor certificateInterceptor = (HttpResponse httpResponse, EntityDetails entityDetails, HttpContext context) -> {
			// Try to get SSL session directly from context first
			SSLSession sslSession = (SSLSession) context.getAttribute(HttpCoreContext.SSL_SESSION);
			if (sslSession != null) {
				try {
					X509Certificate[] certificates = (X509Certificate[]) sslSession.getPeerCertificates();
					CertificateUtil.analyse(certificates);
				} catch (Exception e) {
					//logger.warn("Failed to analyze certificates from SSL session: " + e.getMessage());
				}
			} else {
				//logger.info("No SSL session found in context");
			}
		};

		var connectionManager = new BasicHttpClientConnectionManager(socketFactoryRegistry);
		CloseableHttpClient httpClient = HttpClientBuilder.create()
				.setConnectionManager(connectionManager)
				.addResponseInterceptorLast(certificateInterceptor)
				.build();
		return  httpClient;

	}

	@Bean
	public Supplier<ClientHttpRequestFactory> clientHttpRequestFactory(CloseableHttpClient httpClient) {
		return () -> new HttpComponentsClientHttpRequestFactory(httpClient);
	}
}

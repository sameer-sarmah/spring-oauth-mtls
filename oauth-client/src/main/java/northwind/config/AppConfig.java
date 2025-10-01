package northwind.config;

import java.security.KeyStore;

import javax.net.ssl.SSLContext;

import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.io.BasicHttpClientConnectionManager;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.socket.ConnectionSocketFactory;
import org.apache.hc.client5.http.socket.PlainConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.TrustSelfSignedStrategy;
import org.apache.hc.core5.http.config.Registry;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.apache.hc.core5.ssl.SSLContexts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.http.client.BufferingClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import northwind.service.KeystoreService;

@Configuration
@ComponentScan(basePackages= {"northwind"})
public class AppConfig {
	
	@Autowired
	private KeystoreService keystoreService;
	
	@Value("${key-password}")
	private String keyPwd;
	
	@Autowired
	private RestTemplateBuilder restTemplateBuilder;
	
	private static final Logger LOGGER = LoggerFactory.getLogger(AppConfig.class);
	
	@Bean
	public static PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer() {
		return new PropertySourcesPlaceholderConfigurer();
	}
	
	@Bean
	public HttpClientConnectionManager createConnectionManager(){
		try {	
			KeyStore keystore = keystoreService.readStore();
			SSLContext sslContext = SSLContexts.custom().loadKeyMaterial(keystore, keyPwd.toCharArray())
					.loadTrustMaterial(keystore, new TrustSelfSignedStrategy()).build();
			SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslContext,
					NoopHostnameVerifier.INSTANCE);
	
			Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
					.register("https", sslsf)
					.register("http", new PlainConnectionSocketFactory())
					.build();
	
			var connectionManager = new BasicHttpClientConnectionManager(socketFactoryRegistry);
			return connectionManager;
		}catch (Exception e) {
			LOGGER.error(e.getMessage(),e);
			throw new RuntimeException(e.getMessage());

		} 
	}
	
	@Bean
	public RestTemplate createRestTemplate(CloseableHttpClient httpClient) {		
		ClientHttpRequestFactory httpRequestFactory = new BufferingClientHttpRequestFactory(
				new HttpComponentsClientHttpRequestFactory(httpClient));

		RestTemplate restTemplate = restTemplateBuilder.build();
		restTemplate.setRequestFactory(httpRequestFactory);
		return restTemplate;
	}
	
	@Bean
	public CloseableHttpClient createHttpClient(HttpClientConnectionManager connectionManager) {
		CloseableHttpClient httpClient = HttpClientBuilder.create()
				.setConnectionManager(connectionManager)
				.build();
		return httpClient;
	}

}

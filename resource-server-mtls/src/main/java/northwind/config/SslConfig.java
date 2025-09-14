package northwind.config;

import java.io.IOException;
import java.security.KeyStore;

import javax.net.ssl.SSLContext;


import org.apache.hc.client5.http.ssl.TrustSelfSignedStrategy;
import org.apache.hc.core5.ssl.SSLContexts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import northwind.util.KeyStoreUtil;

@Configuration
public class SslConfig {

	@Value("${client.ssl.key-store}")
	private String keystoreFile;
	@Value("${client.ssl.key-store-password}")
	private String keystorePwd;
	@Value("${client.ssl.key-password}")
	private String keyPwd;
	@Value("${client.ssl.key-store-type}")
	private String keyStoreType;
	@Autowired
	private KeyStoreUtil keyStoreUtil;

	final static Logger logger = LoggerFactory.getLogger(SslConfig.class);
	
	@Bean
	public SSLContext sslContext() {
		try {
			KeyStore keystore = keyStoreUtil.readStore();
			SSLContext sslContext = SSLContexts.custom()
												.loadKeyMaterial(keystore, keyPwd.toCharArray())
												.loadTrustMaterial(keystore, new TrustSelfSignedStrategy())
												.build();
			return sslContext;
		}catch (IOException e) {
				e.printStackTrace();
				logger.error(e.getMessage());
			} catch (Exception e) {
				logger.error(e.getMessage());
		}
		return null;
	}
	
}

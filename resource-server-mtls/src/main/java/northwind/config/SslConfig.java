package northwind.config;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.net.ssl.SSLContext;


import northwind.util.CertificateUtil;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.client5.http.ssl.TrustSelfSignedStrategy;
import org.apache.hc.core5.ssl.SSLContexts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SslConfig {

	@Value("${key-store}")
	private String keystoreFile;
	@Value("${key-store-password}")
	private String keystorePwd;
	@Value("${key-password}")
	private String keyPwd;
	@Value("${key-store-type}")
	private String keyStoreType;

	final static Logger logger = LoggerFactory.getLogger(SslConfig.class);
	
	@Bean
	public SSLContext sslContext() {
		try {
			KeyStore keystore = readStore();
			SSLContext sslContext = SSLContexts.custom()
								.loadKeyMaterial(keystore, keyPwd.toCharArray())
								.loadTrustMaterial(new TrustAllStrategy())
							//	.loadTrustMaterial(keystore, (chain, authType) -> true) // Accept all certificates, including expired
								.build();
			return sslContext;
		}catch (IOException e) {
						logger.error(e.getMessage());
					} catch (Exception e) {
						logger.error(e.getMessage());
			}
		return null;
	}

	private KeyStore readStore() throws Exception {
		try (InputStream keyStoreStream = this.getClass().getClassLoader().getSystemResourceAsStream(keystoreFile)) {
			KeyStore keyStore = KeyStore.getInstance(keyStoreType);
			keyStore.load(keyStoreStream, keystorePwd.toCharArray());

			// Retrieve list of X509Certificate from KeyStore and invoke CertificateUtil.analyse(certificate)
			Enumeration<String> aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				Certificate cert = keyStore.getCertificate(alias);
				if (cert instanceof X509Certificate) {
					CertificateUtil.analyse((X509Certificate) cert);
				}
			}

			return keyStore;
		}
	}
	
}

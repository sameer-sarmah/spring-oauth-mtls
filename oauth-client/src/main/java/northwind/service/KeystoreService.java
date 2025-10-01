package northwind.service;

import java.io.InputStream;
import java.security.KeyStore;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class KeystoreService {

	@Value("${key-store-file}")
	private String keystoreFile;
	@Value("${key-store-password}")
	private String keystorePwd;
	@Value("${key-password}")
	private String keyPwd;
	@Value("${key-store-type}")
	private String keyStoreType;
	
	public KeyStore readStore() throws Exception {
		try (InputStream keyStoreStream = this.getClass().getClassLoader().getSystemResourceAsStream(keystoreFile)) {
			KeyStore keyStore = KeyStore.getInstance(keyStoreType);
			keyStore.load(keyStoreStream, keystorePwd.toCharArray());
			return keyStore;
		}
	}
}

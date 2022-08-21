package northwind.util;

import java.io.InputStream;
import java.security.KeyStore;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class KeyStoreUtil {
	@Value("${client-key-store-file}")
	private String keystoreFile;
	@Value("${client.ssl.key-store-password}")
	private String keystorePwd;
	@Value("${client.ssl.key-password}")
	private String keyPwd;
	@Value("${client.ssl.key-store-type}")
	private String keyStoreType;

	public KeyStore readStore() throws Exception {
		try (InputStream keyStoreStream = this.getClass().getClassLoader().getSystemResourceAsStream(keystoreFile)) {
			KeyStore keyStore = KeyStore.getInstance(keyStoreType);
			keyStore.load(keyStoreStream, keystorePwd.toCharArray());
			return keyStore;
		}
	}
}

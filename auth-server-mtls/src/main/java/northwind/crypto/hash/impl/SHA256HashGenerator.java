package northwind.crypto.hash.impl;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import northwind.crypto.hash.api.IHashGenerator;

@Component
public class SHA256HashGenerator implements IHashGenerator{
	
	private static final Logger LOGGER = LoggerFactory.getLogger(SHA256HashGenerator.class);
	
	@Override
	public SecretKey generateSecretKey() {
		SecretKey hmacKey;
		try {
			hmacKey = KeyGenerator.getInstance("HmacSha256").generateKey();
			LOGGER.info("SHA256 hash generated");
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return hmacKey;
	}
}

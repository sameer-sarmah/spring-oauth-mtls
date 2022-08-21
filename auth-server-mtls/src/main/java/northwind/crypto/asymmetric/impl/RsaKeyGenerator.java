package northwind.crypto.asymmetric.impl;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import northwind.crypto.api.KeyPairType;
import northwind.crypto.asymmetric.api.IKeyGenerator;
import northwind.util.TrustStoreUtil;

@Component
public class RsaKeyGenerator implements IKeyGenerator{
	
	private static final Logger LOGGER = LoggerFactory.getLogger(RsaKeyGenerator.class);

	@Override
	public KeyPair generateKey() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
			PrivateKey privateKey = keyPair.getPrivate();
			PublicKey publicKey = keyPair.getPublic();
			TrustStoreUtil.analysePrivateKey(privateKey);
			TrustStoreUtil.analysePublicKey(publicKey);
			LOGGER.info("RSA Private key and Public key generated");
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}

	@Override
	public KeyPairType getType() {
		return KeyPairType.RSA;
	}
}

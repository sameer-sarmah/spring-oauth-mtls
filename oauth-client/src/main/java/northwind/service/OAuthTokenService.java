package northwind.service;

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import northwind.util.Constants;

@Component
public class OAuthTokenService {
	
	@Value("${oauth-token-url}")
	private String oauthTokenUrl;
	
	@Value("${oauth-client-id}")
	private String clientId;
	
	@Autowired
	private RestTemplate restTemplate;
	
	
	private static final Logger LOGGER = LoggerFactory.getLogger(OAuthTokenService.class);

	private HttpEntity<MultiValueMap<String, String>> createHttpEntity() {
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
		form.add(Constants.CLIENT_ID, clientId);
		form.add(Constants.GRANT_TYPE, Constants.CLIENT_CRED);
		form.add(Constants.CLIENT_SCOPES, "product.read product.write");
		return new HttpEntity<>(form, headers);
	}
	
	public Optional<OAuth2Response> generateOAuthToken() {
		LOGGER.info("{} generating oauth2 access token");
		HttpEntity<MultiValueMap<String, String>> httpEntity = createHttpEntity();
		try {
			ResponseEntity<OAuth2Response> response = restTemplate.postForEntity(oauthTokenUrl, httpEntity, OAuth2Response.class);
			LOGGER.info("{} oauth2 access token generated successfully");
			return Optional.of( response.getBody());	
		} catch (Exception e) {
			LOGGER.error(e.getMessage(), e);
		}
		return Optional.empty();
	}
	
}

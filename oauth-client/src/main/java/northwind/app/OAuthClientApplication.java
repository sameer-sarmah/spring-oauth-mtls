package northwind.app;

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Import;

import northwind.config.AppConfig;
import northwind.service.OAuth2Response;
import northwind.service.OAuthTokenService;





@SpringBootApplication
@ComponentScan(basePackages = "northwind")
@Import({AppConfig.class})
public class OAuthClientApplication  implements ApplicationRunner {
	
	@Autowired
	private OAuthTokenService oAuthTokenService;
	
	private static final Logger LOGGER = LoggerFactory.getLogger(OAuthClientApplication.class);
	
	public static void main(String[] args) {
		SpringApplication.run(OAuthClientApplication.class, args);
		LOGGER.info("##########OAuthClientApplication########");
		
	}

	@Override
	public void run(ApplicationArguments args) throws Exception {
//		Optional<OAuth2Response> response= oAuthTokenService.generateOAuthToken();
//		if(response.isPresent()) {
//			LOGGER.info("Access Token: "+response.get().getAccess_token());
//		}	
		oAuthTokenService.invokeResourceUrl();
	}

}
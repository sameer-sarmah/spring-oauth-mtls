package northwind.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.Import;

import northwind.config.AuthServerConfig;

@SpringBootApplication
@Import({AuthServerConfig.class})
public class AuthorizationServerMtls extends SpringBootServletInitializer{
	
    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
    	return application.sources(AuthorizationServerMtls.class);
    }

	public static void main(String[] args) {
		SpringApplication.run(AuthorizationServerMtls.class, args);
		System.err.println("##########AuthorizationServer MTLS#######");
	}
	
}

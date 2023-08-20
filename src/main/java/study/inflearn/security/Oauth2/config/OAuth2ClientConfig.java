package study.inflearn.security.Oauth2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
public class OAuth2ClientConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests(authRequest -> authRequest
                .antMatchers("/", "/oauth2Login", "/client").permitAll()
                .anyRequest().authenticated());

        http
                .oauth2Client(Customizer.withDefaults());

        /*
        http
                .logout().invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .clearAuthentication(true)
        ;
        */

        return http.build();
    }
}

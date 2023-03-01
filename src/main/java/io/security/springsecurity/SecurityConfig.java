package io.security.springsecurity;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserDetailsService userDetailsService;

    @Bean
    protected SecurityFilterChain config(HttpSecurity http) throws Exception {
        return http
                    .authorizeRequests()
                    .anyRequest()
                    .authenticated()
                .and()
                    .formLogin()
                    .loginPage("/loginPage")
                    .defaultSuccessUrl("/")
                    .failureUrl("/loginPage")
                    .usernameParameter("userId")
                    .passwordParameter("passwd")
                    .loginProcessingUrl("/login_proc")
                    .successHandler((req, res, auth) -> res.sendRedirect("/"))
                    .failureHandler((req, res, auth) -> res.sendRedirect("/login"))
                    .permitAll()
                .and()
                    .logout()
                    .logoutUrl("/logout")
                    .logoutSuccessUrl("/login")
                    .addLogoutHandler((req, res, auth) -> req.getSession().invalidate())
                    .logoutSuccessHandler((req, res, auth) -> res.sendRedirect("/login"))
                    .deleteCookies("remember-me")
                .and()
                    .rememberMe()
                    .rememberMeParameter("remember")
                    .tokenValiditySeconds(3600)
                    .userDetailsService(userDetailsService)
                .and()
                .build();
    }
}

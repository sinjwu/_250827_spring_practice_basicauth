package com.example._250827_spring_practice_basicauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.HttpBasicDsl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.builder()
                .username("user")
                .password(passwordEncoder().encode("password")).roles("USER").build();
        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder().encode("admin123")).roles("USER", "ADMIN").build();
        UserDetails apiUser = User.builder()
                .username("apiuser")
                .password(passwordEncoder().encode("api123")).roles("API").build();
        UserDetails guest = User.builder()
                .username("guest")
                .password(passwordEncoder().encode("guest")).authorities("READ_ONLY").build();
        return new InMemoryUserDetailsManager(user, admin, apiUser, guest);
    }
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(auth -> auth.requestMatchers("/", "/public/**", "/css/**", "/js/**").permitAll()
                        .requestMatchers("/api/**").hasAnyRole("API", "ADMIN")
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .requestMatchers("/user/**").hasAnyRole("USER", "ADMIN")
                        .requestMatchers("/dashboard").authenticated()
                        .anyRequest().authenticated()
                ).formLogin(form -> form.loginPage("/login").permitAll()
                        .defaultSuccessUrl("/dashboard", true).failureUrl("/login?error=true")
                        .usernameParameter("username")
                        .passwordParameter("password"))
                .httpBasic(basic -> basic.realmName("BasicAuth"))
                .logout(logout -> logout.logoutUrl("/logout").logoutSuccessUrl("/login?logout=true").invalidateHttpSession(true).deleteCookies("JSESSIONID").permitAll())
                .csrf(csrf -> csrf.ignoringRequestMatchers("/api/**")).build();
    }
}

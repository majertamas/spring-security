package com.example.springsecurity.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.example.springsecurity.security.ApplicationUserPermission.COURSE_WRITE;
import static com.example.springsecurity.security.ApplicationUserRole.ADMIN;
import static com.example.springsecurity.security.ApplicationUserRole.ADMIN_TRAINEE;
import static com.example.springsecurity.security.ApplicationUserRole.STUDENT;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    public static final String MANAGEMENT_API = "/management/api/**";

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                .antMatchers(HttpMethod.DELETE, MANAGEMENT_API).hasAnyAuthority(COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.POST, MANAGEMENT_API).hasAnyAuthority(COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.PUT, MANAGEMENT_API).hasAnyAuthority(COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.GET, MANAGEMENT_API).hasAnyRole(ADMIN.name(), ADMIN_TRAINEE.name())
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails annaUser = User.builder()
                .username("anna")
                .password(passwordEncoder.encode("pw1"))
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails lindaAdmin = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("pw2"))
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails tomAdmin = User.builder()
                .username("tom")
                .password(passwordEncoder.encode("pw3"))
                .authorities(ADMIN_TRAINEE.getGrantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(
                annaUser,
                lindaAdmin,
                tomAdmin
        );
    }
}

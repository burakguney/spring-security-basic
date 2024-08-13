package com.burak.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.burak.security.entity.AuthUser;
import com.burak.security.service.AuthUserService;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http.csrf((csrf) -> csrf.disable())
				.authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests
						.requestMatchers("/api/admin/**").hasAuthority("ADMIN")
						.anyRequest().permitAll())
				.httpBasic(Customizer.withDefaults());

		return http.build();
	}

	@Bean
	UserDetailsService userDetailsService(AuthUserService userService) {
		return username -> {
			AuthUser user = userService.findByUsername(username);
			if (user == null) {
				throw new UsernameNotFoundException("Kullanıcı bulunamadı: " + username);
			}
			return org.springframework.security.core.userdetails.User.withUsername(user.getUsername())
					.password(user.getPassword()).authorities(user.getRole().toString()).build();
		};
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
			throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}

}

/**
 * ContainerProxy
 *
 * Copyright (C) 2016-2018 Open Analytics
 *
 * ===========================================================================
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Apache License as published by
 * The Apache Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Apache License for more details.
 *
 * You should have received a copy of the Apache License
 * along with this program.  If not, see <http://www.apache.org/licenses/>
 */
package eu.openanalytics.containerproxy.auth.impl;

import java.util.Arrays;
import java.util.Collection;
import java.util.ArrayList;
import java.util.Base64;

import javax.inject.Inject;
import org.apache.commons.codec.binary.StringUtils;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.rcp.RemoteAuthenticationException;
import org.springframework.security.authentication.rcp.RemoteAuthenticationManager;
import org.springframework.security.authentication.rcp.RemoteAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import com.google.common.collect.Lists;

import eu.openanalytics.containerproxy.auth.IAuthenticationBackend;

/**
 * Web service authentication method where user/password combinations are
 * checked by a HTTP call to a remote web service.
 */
public class TanAuthenticationBackend implements IAuthenticationBackend {
	
	public static final String NAME = "tan";

	@Inject
	private Environment environment;

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public boolean hasAuthorization() {
		return true;
	}

	@Override
	public void configureHttpSecurity(HttpSecurity http) throws Exception {
		// Nothing to do.
	}
	
	@Override
	public String getLogoutSuccessURL() {
		String logoutURL = environment.getProperty("proxy.tan.logout-url");
		if (logoutURL == null || logoutURL.trim().isEmpty()) logoutURL = IAuthenticationBackend.super.getLogoutSuccessURL();
		return logoutURL;
	}
	
	@Override
	public void configureAuthenticationManagerBuilder(AuthenticationManagerBuilder auth) throws Exception {
		RemoteAuthenticationProvider authenticationProvider = new RemoteAuthenticationProvider();
		authenticationProvider.setRemoteAuthenticationManager(new RemoteAuthenticationManager() {

			@Override
			public Collection<? extends GrantedAuthority> attemptAuthentication(String username, String token)
					throws RemoteAuthenticationException {

				try {
					if (true) {
						// username的形式一定要是id(name)
						// 把GROUP加进去
						// password就是token，目前就是GROUP信息
						String groupString = StringUtils.newStringUtf8(Base64.getDecoder().decode(token));
						String[] groups = groupString.split("\\|");
						ArrayList<GrantedAuthority> out = new ArrayList<>();
						for (String group : groups) {
							out.add(new SimpleGrantedAuthority(group));
						}
						String userId = username.replaceAll("\\(.*\\)", "").toUpperCase();
						// 永远把ID号加进去
						out.add(new SimpleGrantedAuthority(userId));
						return out;
					}
					throw new AuthenticationServiceException("Unknown response received.");	
				} catch (HttpClientErrorException e) {
					throw new BadCredentialsException("Invalid username or password.");
				} catch (RestClientException e) {
					throw new AuthenticationServiceException("Internal error " + e.getMessage());
				}

			}
		});
		auth.authenticationProvider(authenticationProvider);
	}

}

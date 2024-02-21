package com.keycloak.springmvc.config;

import lombok.Getter;
import lombok.Setter;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "keycloak")
public class KeycloakProperties {
	
	private String realm;
	private String serverUrl;
	private String adminClientUuid;
	private String adminClientId;
	private String adminClientSecret;
	private String grantType;
	private Keycloak keycloak;
	
	public Keycloak getKeycloakInstance() {
		if (keycloak == null) {
			keycloak = KeycloakBuilder
				.builder().serverUrl(serverUrl)
				.realm(realm)
				.grantType(grantType)
				.clientId(adminClientId)
				.clientSecret(adminClientSecret)
				.build();
		}
		return keycloak;
	}
}

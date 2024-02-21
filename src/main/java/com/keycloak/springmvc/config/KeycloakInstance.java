package com.keycloak.springmvc.config;

import lombok.RequiredArgsConstructor;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class KeycloakInstance {
	
	private final KeycloakProperties keycloakProperties;
	private Keycloak keycloak;
	
	public Keycloak getKeycloakInstance() {
		if (keycloak == null) {
			keycloak = KeycloakBuilder
				.builder().serverUrl(keycloakProperties.getServerUrl())
				.realm(keycloakProperties.getRealm())
				.grantType(keycloakProperties.getGrantType())
				.clientId(keycloakProperties.getAdminClientId())
				.clientSecret(keycloakProperties.getAdminClientSecret())
				.build();
		}
		return keycloak;
	}
}

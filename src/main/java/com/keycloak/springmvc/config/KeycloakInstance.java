package com.keycloak.springmvc.config;

import lombok.RequiredArgsConstructor;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.RealmResource;
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
	
	public RealmResource getRealmResource() {
		String realm = keycloakProperties.getRealm();
		return getKeycloakInstance().realm(realm);
	}
	
	public ClientResource getClientResource() {
		RealmResource realmResource = getRealmResource();
		String clientId = keycloakProperties.getAdminClientUuid();
		return realmResource.clients().get(clientId);
	}
}

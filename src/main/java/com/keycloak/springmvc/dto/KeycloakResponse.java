package com.keycloak.springmvc.dto;

import java.util.List;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class KeycloakResponse {
	private List<KeycloakResource> resources;
	
	public KeycloakResponse(List<KeycloakResource> resources) {
		this.resources = resources;
	}
}

package com.keycloak.springmvc.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class KeycloakScope extends KeycloakBasic {
	private String status;
	
	public KeycloakScope(String id, String name, String displayName) {
		super(id, name, displayName);
	}
}

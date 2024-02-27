package com.keycloak.springmvc.dto;

import java.util.ArrayList;
import java.util.List;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class KeycloakResource extends KeycloakBasic {
	private List<KeycloakScope> scopes;
	private String status;
	
	public void addScopes(KeycloakScope scope) {
		List<KeycloakScope> temps = scopes != null ? scopes : new ArrayList<>();
		temps.add(scope);
		scopes = temps;
	}
	
	public KeycloakResource(String id, String name, String displayName) {
		super(id, name, displayName);
	}
}
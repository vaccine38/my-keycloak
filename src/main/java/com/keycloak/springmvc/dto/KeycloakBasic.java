package com.keycloak.springmvc.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class KeycloakBasic {
	private String id;
	private String name;
	private String displayName;
	
	public KeycloakBasic(String id, String name, String displayName) {
		this.id = id;
		this.name = name;
		this.displayName = displayName;
	}
}

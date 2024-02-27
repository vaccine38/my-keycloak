package com.keycloak.springmvc.dto;

import java.util.List;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class KeycloakUpdatePerRequest {
	
	private List<KeycloakUpdatePerItem> items;
}

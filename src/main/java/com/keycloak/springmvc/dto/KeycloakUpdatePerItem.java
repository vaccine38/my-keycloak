package com.keycloak.springmvc.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class KeycloakUpdatePerItem {
	
	private String resourceId;
	private String scopeId;
	private String status;
	private String permissionId;
	private String negativePermissionId;
}

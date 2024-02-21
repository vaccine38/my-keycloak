package com.keycloak.springmvc.controller;

import com.keycloak.springmvc.config.KeycloakInstance;
import com.keycloak.springmvc.config.KeycloakProperties;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.authorization.AbstractPolicyRepresentation;
import org.keycloak.representations.idm.authorization.PolicyRepresentation;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.ScopePermissionRepresentation;
import org.keycloak.representations.idm.authorization.ScopeRepresentation;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping(
	value = "/permissions",
	produces = MediaType.APPLICATION_JSON_VALUE
)
public class PermissionController {
	
	private static final String PERMISSION_PREFIX = "per::";
	private final KeycloakProperties keycloakProperties;
	private final KeycloakInstance keycloakInstance;
	
	@GetMapping("/list")
	public ResponseEntity<Object> permissionList() {
		// get user context
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null || !authentication.isAuthenticated()) {
			log.error("User not authenticated");
			return null;
		}
		Jwt jwt = (Jwt) authentication.getPrincipal();
		String username = jwt.getClaim("preferred_username");
		String policyId = getPolicyIdByUser(username);
		Assert.notNull(policyId, "Policy not found");
		
		// get keycloak config
		Keycloak keycloak = keycloakInstance.getKeycloakInstance();
		String realm = keycloakProperties.getRealm();
		RealmResource realmResource = keycloak.realm(realm);
		String clientId = keycloakProperties.getAdminClientUuid();
		ClientResource clientResource = realmResource.clients().get(clientId);
		
		Map<String, KeycloakResource> resourceMap = new HashMap<>();
		// get all permissions and their scopes, resources
		clientResource.authorization()
			.policies()
			.policies()
			.stream()
			.filter(s -> s.getName().contains(PERMISSION_PREFIX))
			.forEach(per -> {
				List<ScopeRepresentation> scopes = clientResource.authorization()
					.permissions()
					.scope()
					.findById(per.getId())
					.scopes();
				ScopeRepresentation scope = scopes != null && !scopes.isEmpty() ? scopes.getFirst() : null;
				
				List<ResourceRepresentation> resources = clientResource.authorization()
					.permissions()
					.scope()
					.findById(per.getId())
					.resources();
				Assert.notEmpty(resources, "Resource not found");
				ResourceRepresentation resource = resources.getFirst();
				
				KeycloakResource keycloakResource =
					Optional.ofNullable(resourceMap.get(resource.getId()))
						.orElse(new KeycloakResource(resource.getId(), resource.getName(),
							resource.getDisplayName()));
				if (scope != null) {
					KeycloakScope keycloakScope = new KeycloakScope(
						scope.getId(), scope.getName(), scope.getDisplayName(), per.getId());
					keycloakResource.addScopes(keycloakScope);
				} else {
					keycloakResource.setPermissionId(per.getId());
				}
				
				resourceMap.put(resource.getId(), keycloakResource);
			});
		
		// get user permissions by his policy
		List<String> myPermissions = clientResource.authorization()
			.permissions()
			.scope()
			.findById(policyId)
			.dependentPolicies()
			.stream()
			.map(PolicyRepresentation::getId)
			.toList();
		
		List<KeycloakResource> resourceList = resourceMap.values().stream().toList();
		KeycloakResponse response = new KeycloakResponse(resourceList, myPermissions);
		return ResponseEntity.ok(response);
	}
	
	@PostMapping("/associate")
	public ResponseEntity<Object> associatePermission(@RequestBody KeycloakAssociatePermissionRequest request) {
		// get user context
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null || !authentication.isAuthenticated()) {
			log.error("User not authenticated");
			return null;
		}
		Jwt jwt = (Jwt) authentication.getPrincipal();
		String username = jwt.getClaim("preferred_username");
		String policyId = getPolicyIdByUser(username);
		Assert.notNull(policyId, "Policy not found");
		
		// get keycloak config
		Keycloak keycloak = keycloakInstance.getKeycloakInstance();
		String realm = keycloakProperties.getRealm();
		RealmResource realmResource = keycloak.realm(realm);
		String clientId = keycloakProperties.getAdminClientUuid();
		ClientResource clientResource = realmResource.clients().get(clientId);
		
		// get all permissions associated to user policy
		List<String> myPermissions = clientResource.authorization()
			.permissions()
			.scope()
			.findById(policyId)
			.dependentPolicies()
			.stream()
			.map(PolicyRepresentation::getId)
			.toList();
		List<String> requestPermissions = Optional.ofNullable(request.getPermissionIds())
			.orElse(new ArrayList<>());
		List<String> removePermissions = myPermissions.stream()
			.filter(s -> !requestPermissions.contains(s))
			.toList();
		for (String removeId : removePermissions) {
			ScopePermissionRepresentation update = clientResource.authorization()
				.permissions()
				.scope()
				.findById(removeId)
				.toRepresentation();
			// find all associated policies and remove policyId
			Set<String> associatedPolIds = clientResource.authorization()
				.permissions()
				.scope()
				.findById(removeId)
				.associatedPolicies()
				.stream()
				.map(AbstractPolicyRepresentation::getId)
				.collect(Collectors.toSet());
			associatedPolIds.remove(policyId);
			update.setPolicies(associatedPolIds);
			// update
			clientResource.authorization()
				.permissions()
				.scope()
				.findById(removeId)
				.update(update);
		}
		
		List<String> addPermissions = requestPermissions.stream()
			.filter(s -> !myPermissions.contains(s))
			.toList();
		for (String addId : addPermissions) {
			ScopePermissionRepresentation update = clientResource.authorization()
				.permissions()
				.scope()
				.findById(addId)
				.toRepresentation();
			// find all associated policies and add policyId
			Set<String> associatedPolIds = clientResource.authorization()
				.permissions()
				.scope()
				.findById(addId)
				.associatedPolicies()
				.stream()
				.map(AbstractPolicyRepresentation::getId)
				.collect(Collectors.toSet());
			associatedPolIds.add(policyId);
			update.setPolicies(associatedPolIds);
			// update
			clientResource.authorization()
				.permissions()
				.scope()
				.findById(addId)
				.update(update);
		}
		return ResponseEntity.ok(true);
	}
	
	private String getPolicyIdByUser(String userName) {
		Map<String, String> policyMap = new HashMap<>();
		policyMap.put("chinhnq", "90839873-496e-4e08-89e7-6f683d3c4330");
		policyMap.put("longdk", "46591a2e-462b-40ce-81ed-870947185cf7");
		return policyMap.get(userName);
	}
	
	@Data
	@NoArgsConstructor
	static class KeycloakAssociatePermissionRequest {
		private List<String> permissionIds;
	}
	
	@Data
	@NoArgsConstructor
	static class KeycloakResponse {
		private List<KeycloakResource> resources;
		private List<String> myPermissions;
		
		public KeycloakResponse(List<KeycloakResource> resources, List<String> myPermissions) {
			this.resources = resources;
			this.myPermissions = myPermissions;
		}
	}
	
	@Data
	@NoArgsConstructor
	static class KeycloakBasic {
		private String id;
		private String name;
		private String displayName;
		
		public KeycloakBasic(String id, String name, String displayName) {
			this.id = id;
			this.name = name;
			this.displayName = displayName;
		}
	}
	
	@Data
	@EqualsAndHashCode(callSuper = true)
	@NoArgsConstructor
	static class KeycloakScope extends KeycloakBasic {
		private String permissionId;
		
		public KeycloakScope(String id, String name, String displayName, String permissionId) {
			super(id, name, displayName);
			this.permissionId = permissionId;
		}
	}
	
	@Data
	@EqualsAndHashCode(callSuper = true)
	@NoArgsConstructor
	static class KeycloakResource extends KeycloakBasic {
		private List<KeycloakScope> scopes;
		private String permissionId;
		
		public void addScopes(KeycloakScope scope) {
			List<KeycloakScope> temps = scopes != null ? scopes : new ArrayList<>();
			temps.add(scope);
			scopes = temps;
		}
		
		public KeycloakResource(String id, String name, String displayName) {
			super(id, name, displayName);
		}
	}
}

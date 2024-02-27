package com.keycloak.springmvc.controller;

import com.keycloak.springmvc.config.KeycloakInstance;
import com.keycloak.springmvc.config.KeycloakProperties;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
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
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.authorization.AbstractPolicyRepresentation;
import org.keycloak.representations.idm.authorization.PolicyEvaluationRequest;
import org.keycloak.representations.idm.authorization.PolicyEvaluationResponse;
import org.keycloak.representations.idm.authorization.PolicyRepresentation;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.RolePolicyRepresentation;
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
//		String policyId = getPolicyIdByUser(username);
//		Assert.notNull(policyId, "Policy not found");
		
		// get keycloak config
		Keycloak keycloak = keycloakInstance.getKeycloakInstance();
		String realm = keycloakProperties.getRealm();
		RealmResource realmResource = keycloak.realm(realm);
		String clientId = keycloakProperties.getAdminClientUuid();
		ClientResource clientResource = realmResource.clients().get(clientId);
		
		List<ResourceRepresentation> resourceLst =
			clientResource.authorization().resources().resources();
//		resourceLst = resourceLst.stream()
//			.filter(s -> s.getScopes() != null && !s.getScopes().isEmpty())
//			.toList();
		String keycloakUserId = getKeycloakIdByUser(username);
		PolicyEvaluationResponse evaluationRes =
			evaluatePermission(clientResource, keycloakUserId, resourceLst);
		List<String> resourceOrScopePermitIds = new ArrayList<>();
		Optional.ofNullable(evaluationRes.getResults())
			.orElse(new ArrayList<>())
			.stream()
			.filter(s -> s.getStatus() != null && "PERMIT".equals(s.getStatus().toString()))
			.forEach(s -> {
				List<ScopeRepresentation> allowedScopes = s.getAllowedScopes();
				if (allowedScopes != null && !allowedScopes.isEmpty()) {
					allowedScopes.stream()
						.map(sc -> s.getResource().getId() + sc.getId())
						.forEach(resourceOrScopePermitIds::add);
				} else {
					resourceOrScopePermitIds.add(s.getResource().getId());
				}
			});
		
		List<KeycloakResource> keycloakResources = resourceLst.stream()
			.map(resource -> {
				KeycloakResource ks = new KeycloakResource(resource.getId(), resource.getName(),
					resource.getDisplayName());
				
				Set<ScopeRepresentation> scopes = resource.getScopes();
				scopes.stream()
					.map(s -> new KeycloakScope(s.getId(), s.getName(), s.getDisplayName()))
					.forEach(s -> {
						s.setStatus(
							resourceOrScopePermitIds.contains(resource.getId() + s.getId()) ?
								"PERMIT" : "DENY");
						ks.addScopes(s);
					});
				if (scopes.isEmpty()) {
					ks.setStatus(
						resourceOrScopePermitIds.contains(resource.getId()) ? "PERMIT" : "DENY");
				}
				return ks;
			})
			.toList();
		
		KeycloakResponse response = new KeycloakResponse(keycloakResources, null);
		return ResponseEntity.ok(response);

//		Map<String, KeycloakResource> resourceMap = new HashMap<>();
//		// get all permissions and their scopes, resources
//		clientResource.authorization()
//			.policies()
//			.policies()
//			.stream()
//			.filter(s -> s.getName().contains(PERMISSION_PREFIX))
//			.forEach(per -> {
//				List<ScopeRepresentation> scopes = clientResource.authorization()
//					.permissions()
//					.scope()
//					.findById(per.getId())
//					.scopes();
//				ScopeRepresentation scope = scopes != null && !scopes.isEmpty() ? scopes.getFirst() : null;
//
//				List<ResourceRepresentation> resources = clientResource.authorization()
//					.permissions()
//					.scope()
//					.findById(per.getId())
//					.resources();
//				Assert.notEmpty(resources, "Resource not found");
//				ResourceRepresentation resource = resources.getFirst();
//
//				KeycloakResource keycloakResource =
//					Optional.ofNullable(resourceMap.get(resource.getId()))
//						.orElse(new KeycloakResource(resource.getId(), resource.getName(),
//							resource.getDisplayName()));
//				if (scope != null) {
//					KeycloakScope keycloakScope = new KeycloakScope(
//						scope.getId(), scope.getName(), scope.getDisplayName(), per.getId());
//					keycloakResource.addScopes(keycloakScope);
//				} else {
//					keycloakResource.setPermissionId(per.getId());
//				}
//
//				resourceMap.put(resource.getId(), keycloakResource);
//			});
//
//		// get user permissions by his policy
//		List<String> myPermissions = clientResource.authorization()
//			.permissions()
//			.scope()
//			.findById(policyId)
//			.dependentPolicies()
//			.stream()
//			.map(PolicyRepresentation::getId)
//			.toList();
//
//		List<KeycloakResource> resourceList = resourceMap.values().stream().toList();
//		KeycloakResponse response = new KeycloakResponse(resourceList, myPermissions);
//		return ResponseEntity.ok(response);
	}
	
	private PolicyEvaluationResponse evaluatePermission(ClientResource clientResource,
	                                                    String keycloakUserId,
	                                                    List<ResourceRepresentation> resourceList) {
		PolicyEvaluationRequest evaluationRequest = new PolicyEvaluationRequest();
		evaluationRequest.setUserId(keycloakUserId);
		evaluationRequest.setResources(resourceList);
		return clientResource.authorization().policies().evaluate(evaluationRequest);
	}
	
	@PostMapping("/associate")
	public ResponseEntity<Object> associatePermission(
		@RequestBody KeycloakAssociatePermissionRequest request) {
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
	
	private String getKeycloakIdByUser(String userName) {
		Map<String, String> policyMap = new HashMap<>();
		policyMap.put("chinhnq", "664f67c1-446d-49e0-85a1-4f9b5fbc4e66");
		policyMap.put("longdk", "4ad24584-e1cd-4ab3-b109-37774f180ce8");
		policyMap.put("anhho", "b25675a4-bc97-4d5e-867c-790146bc98e0");
		policyMap.put("nhungdo", "b9149390-919f-45ec-ab8c-88a9ce78a987");
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
		private String status;
		
		public KeycloakScope(String id, String name, String displayName) {
			super(id, name, displayName);
		}
	}
	
	@Data
	@EqualsAndHashCode(callSuper = true)
	@NoArgsConstructor
	static class KeycloakResource extends KeycloakBasic {
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
	
	public static final String ROLE_ONE = "rol::one";
	public static final String ROLE_SUB1 = "rol::sub1";
	public static final String ROLE_SUB2 = "rol::sub2";
	public static final String GROUP_ONE = "grp::one";
	public static final String GROUP_SUB1 = "grp::sub1";
	public static final String GROUP_SUB2 = "grp::sub2";
	public static final String POLICY_ONE = "pol::one";
	public static final String POLICY_SUB1 = "pol::sub1";
	public static final String POLICY_SUB2 = "pol::sub2";
	
	@PostMapping("/groups")
	public ResponseEntity<Object> createGroup() {
		Keycloak keycloak = keycloakInstance.getKeycloakInstance();
		String realm = keycloakProperties.getRealm();
		RealmResource realmResource = keycloak.realm(realm);
		
		// roles
		List<RoleRepresentation> roles = realmResource.roles().list();
		
		roles.stream().filter(s -> ROLE_ONE.equals(s.getName())).findFirst().ifPresentOrElse(
			roleRepresentation -> {
			},
			() -> {
				RoleRepresentation role1 = new RoleRepresentation();
				role1.setName(ROLE_ONE);
				realmResource.roles().create(role1);
			});
		
		roles.stream().filter(s -> ROLE_SUB1.equals(s.getName())).findFirst().ifPresentOrElse(
			roleRepresentation -> {
			},
			() -> {
				RoleRepresentation roleSub1 = new RoleRepresentation();
				roleSub1.setName(ROLE_SUB1);
				realmResource.roles().create(roleSub1);
			});
		
		roles.stream().filter(s -> ROLE_SUB2.equals(s.getName())).findFirst().ifPresentOrElse(
			roleRepresentation -> {
			},
			() -> {
				RoleRepresentation roleSub2 = new RoleRepresentation();
				roleSub2.setName(ROLE_SUB2);
				realmResource.roles().create(roleSub2);
			});
		
		roles = realmResource.roles().list();
		RoleRepresentation group1Role =
			roles.stream().filter(s -> ROLE_ONE.equals(s.getName())).findFirst().orElse(null);
		RoleRepresentation sub1Role =
			roles.stream().filter(s -> ROLE_SUB1.equals(s.getName())).findFirst().orElse(null);
		RoleRepresentation sub2Role =
			roles.stream().filter(s -> ROLE_SUB2.equals(s.getName())).findFirst().orElse(null);
		
		// groups
		List<GroupRepresentation> groups = realmResource.groups().groups();
		groups.stream().filter(s -> GROUP_ONE.equals(s.getName())).findFirst().ifPresentOrElse(
			groupRepresentation -> {
			},
			() -> {
				GroupRepresentation group1 = new GroupRepresentation();
				group1.setName(GROUP_ONE);
				realmResource.groups().add(group1);
			});
		
		groups = realmResource.groups().groups();
		GroupRepresentation groupOne =
			groups.stream().filter(s -> GROUP_ONE.equals(s.getName())).findFirst().orElse(null);
		if (groupOne == null) {
			return ResponseEntity.ok(false);
		}
		realmResource.groups().group(groupOne.getId()).roles().realmLevel()
			.add(Collections.singletonList(group1Role));
		
		groups.stream().filter(s -> GROUP_SUB1.equals(s.getName())).findFirst().ifPresentOrElse(
			groupRepresentation -> {
			},
			() -> {
				GroupRepresentation subGroup1 = new GroupRepresentation();
				subGroup1.setName(GROUP_SUB1);
				subGroup1.setParentId(groupOne.getId());
				realmResource.groups().group(groupOne.getId()).subGroup(subGroup1);
			});
		
		groups.stream().filter(s -> GROUP_SUB2.equals(s.getName())).findFirst().ifPresentOrElse(
			groupRepresentation -> {
			},
			() -> {
				GroupRepresentation subGroup2 = new GroupRepresentation();
				subGroup2.setName(GROUP_SUB2);
				subGroup2.setParentId(groupOne.getId());
				realmResource.groups().group(groupOne.getId()).subGroup(subGroup2);
			});
		
		List<GroupRepresentation> subGroups = realmResource.groups().group(groupOne.getId())
				.getSubGroups(null, null, false);
		subGroups.stream().filter(s -> GROUP_SUB1.equals(s.getName())).findFirst().ifPresent(
			groupSub1 -> realmResource.groups().group(groupSub1.getId()).roles().realmLevel()
				.add(Collections.singletonList(sub1Role)));
		subGroups.stream().filter(s -> GROUP_SUB2.equals(s.getName())).findFirst().ifPresent(
			groupSub2 -> realmResource.groups().group(groupSub2.getId()).roles().realmLevel()
				.add(Collections.singletonList(sub2Role)));
		
		// policies
		String clientId = keycloakProperties.getAdminClientUuid();
		ClientResource clientResource = realmResource.clients().get(clientId);
		
		clientResource.authorization().policies().policies().stream()
			.filter(s -> POLICY_ONE.equals(s.getName())).findFirst().ifPresentOrElse(
			policyRepresentation -> {
			},
			() -> {
				RolePolicyRepresentation rolePolicy = new RolePolicyRepresentation();
				rolePolicy.setName(POLICY_ONE);
				Set<RolePolicyRepresentation.RoleDefinition> roleDefinitions = new HashSet<>();
				assert group1Role != null;
				roleDefinitions.add(new RolePolicyRepresentation.RoleDefinition(group1Role.getId(), true));
				rolePolicy.setRoles(roleDefinitions);
				clientResource.authorization().policies().role().create(rolePolicy);
			});
		
		clientResource.authorization().policies().policies().stream()
			.filter(s -> POLICY_SUB1.equals(s.getName())).findFirst().ifPresentOrElse(
				policyRepresentation -> {
				},
				() -> {
					RolePolicyRepresentation rolePolicy = new RolePolicyRepresentation();
					rolePolicy.setName(POLICY_SUB1);
					Set<RolePolicyRepresentation.RoleDefinition> roleDefinitions = new HashSet<>();
					assert sub1Role != null;
					roleDefinitions.add(new RolePolicyRepresentation.RoleDefinition(sub1Role.getId(), true));
					rolePolicy.setRoles(roleDefinitions);
					clientResource.authorization().policies().role().create(rolePolicy);
				});
		
		clientResource.authorization().policies().policies().stream()
			.filter(s -> POLICY_SUB2.equals(s.getName())).findFirst().ifPresentOrElse(
				policyRepresentation -> {
				},
				() -> {
					RolePolicyRepresentation rolePolicy = new RolePolicyRepresentation();
					rolePolicy.setName(POLICY_SUB2);
					Set<RolePolicyRepresentation.RoleDefinition> roleDefinitions = new HashSet<>();
					assert sub2Role != null;
					roleDefinitions.add(new RolePolicyRepresentation.RoleDefinition(sub2Role.getId(), true));
					rolePolicy.setRoles(roleDefinitions);
					clientResource.authorization().policies().role().create(rolePolicy);
				});
		
		return ResponseEntity.ok(true);
	}
}

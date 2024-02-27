package com.keycloak.springmvc.controller;

import com.keycloak.springmvc.config.KeycloakInstance;
import com.keycloak.springmvc.config.KeycloakProperties;
import com.keycloak.springmvc.dto.KeycloakAssociatePerRequest;
import com.keycloak.springmvc.dto.KeycloakResource;
import com.keycloak.springmvc.dto.KeycloakResponse;
import com.keycloak.springmvc.dto.KeycloakScope;
import com.keycloak.springmvc.dto.KeycloakUpdatePerItem;
import com.keycloak.springmvc.dto.KeycloakUpdatePerRequest;
import jakarta.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.authorization.AbstractPolicyRepresentation;
import org.keycloak.representations.idm.authorization.Logic;
import org.keycloak.representations.idm.authorization.PolicyEvaluationRequest;
import org.keycloak.representations.idm.authorization.PolicyEvaluationResponse;
import org.keycloak.representations.idm.authorization.PolicyRepresentation;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.RolePolicyRepresentation;
import org.keycloak.representations.idm.authorization.ScopePermissionRepresentation;
import org.keycloak.representations.idm.authorization.ScopeRepresentation;
import org.keycloak.representations.idm.authorization.UserPolicyRepresentation;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
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
	
	public static final String ROLE_ONE = "rol::one";
	public static final String ROLE_SUB1 = "rol::sub1";
	public static final String ROLE_SUB2 = "rol::sub2";
	public static final String GROUP_ONE = "grp::one";
	public static final String GROUP_SUB1 = "grp::sub1";
	public static final String GROUP_SUB2 = "grp::sub2";
	public static final String POLICY_ONE = "pol::one";
	public static final String POLICY_SUB1 = "pol::sub1";
	public static final String POLICY_SUB2 = "pol::sub2";
	public static final String RES_BOOK = "res::book";
	public static final String RES_PERMISSION = "res::permission";
	public static final String RES_STUDENT = "res::student";
	public static final List<String> managementResList =
		List.of(RES_BOOK, RES_PERMISSION, RES_STUDENT);
	public static final String PERMIT = "PERMIT";
	public static final String DENY = "DENY";
	public static final List<String> allowedStatuses = List.of(PERMIT, DENY);
	public static final String PREFERRED_USERNAME = "preferred_username";
	public static final String NEGATIVE = "negative";
	public static final String POLICY_PREFIX = "pol::";
	private final KeycloakProperties keycloakProperties;
	private final KeycloakInstance keycloakInstance;
	
	@GetMapping("/list")
	public ResponseEntity<Object> permissionList() {
		String username = buildCurrentUserName();
		ClientResource clientResource = keycloakInstance.getClientResource();
		
		List<ResourceRepresentation> resourceLst = clientResource
			.authorization()
			.resources()
			.resources()
			.stream()
			.filter(res -> managementResList.contains(res.getName()))
			.toList();
		String keycloakUserId = getKeycloakIdByUser(username);
		PolicyEvaluationResponse evaluationRes =
			evaluatePermission(clientResource, keycloakUserId, resourceLst);
		List<String> resourceOrScopePermitIds = new ArrayList<>();
		Optional.ofNullable(evaluationRes.getResults())
			.orElse(new ArrayList<>())
			.stream()
			.filter(s -> s.getStatus() != null && PERMIT.equals(s.getStatus().toString()))
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
								PERMIT : DENY);
						ks.addScopes(s);
					});
				if (scopes.isEmpty()) {
					ks.setStatus(
						resourceOrScopePermitIds.contains(resource.getId()) ? PERMIT : DENY);
				}
				return ks;
			})
			.toList();
		
		KeycloakResponse response = new KeycloakResponse(keycloakResources);
		return ResponseEntity.ok(response);
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
		@RequestBody KeycloakAssociatePerRequest request) {
		String username = buildCurrentUserName();
		String policyId = getPolicyIdByUser(username);
		Assert.notNull(policyId, "Policy not found");
		
		ClientResource clientResource = keycloakInstance.getClientResource();
		
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
		
		Set<String> removePerIds = myPermissions.stream()
			.filter(s -> !requestPermissions.contains(s))
			.collect(Collectors.toSet());
		Set<String> addPerIds = requestPermissions.stream()
			.filter(s -> !myPermissions.contains(s))
			.collect(Collectors.toSet());
		
		updatePermissionAssociatedWithPolicy(clientResource, policyId, addPerIds, removePerIds);
		
		return ResponseEntity.ok(true);
	}
	
	private void updatePermissionAssociatedWithPolicy(ClientResource clientResource,
	                                                  String polId,
	                                                  String addPerId,
	                                                  String removePerId) {
		Set<String> addPerIds = addPerId == null ? null : new HashSet<>(List.of(addPerId));
		Set<String> removePerIds = removePerId == null ? null : new HashSet<>(List.of(removePerId));
		updatePermissionAssociatedWithPolicy(clientResource, polId, addPerIds, removePerIds);
	}
	
	private void updatePermissionAssociatedWithPolicy(ClientResource clientResource,
	                                                  String polId,
	                                                  Set<String> addPerIds,
	                                                  Set<String> removePerIds) {
		if (!StringUtils.hasText(polId) || clientResource == null) {
			return;
		}
		removePerIds = removePerIds != null ? removePerIds : new HashSet<>();
		for (String removeId : removePerIds) {
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
			
			if (associatedPolIds.contains(polId)) {
				associatedPolIds.remove(polId);
				update.setPolicies(associatedPolIds);
				clientResource.authorization()
					.permissions()
					.scope()
					.findById(removeId)
					.update(update);
			}
		}
		
		addPerIds = addPerIds != null ? addPerIds : new HashSet<>();
		for (String addId : addPerIds) {
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
			
			if (!associatedPolIds.contains(polId)) {
				associatedPolIds.add(polId);
				update.setPolicies(associatedPolIds);
				clientResource.authorization()
					.permissions()
					.scope()
					.findById(addId)
					.update(update);
			}
		}
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
	
	@PostMapping("/groups")
	public ResponseEntity<Object> createGroup() {
		RealmResource realmResource = keycloakInstance.getRealmResource();
		
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
				try (Response res = realmResource.groups().add(group1)) {
					log.info("Create group: " + res.getStatus());
				} catch (Exception ex) {
					log.error("Create group failed", ex);
				}
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
				try (Response res = realmResource.groups().group(groupOne.getId())
					.subGroup(subGroup1)) {
					log.info("Create sub group: " + res.getStatus());
				} catch (Exception ex) {
					log.error("Create sub group failed", ex);
				}
			});
		
		groups.stream().filter(s -> GROUP_SUB2.equals(s.getName())).findFirst().ifPresentOrElse(
			groupRepresentation -> {
			},
			() -> {
				GroupRepresentation subGroup2 = new GroupRepresentation();
				subGroup2.setName(GROUP_SUB2);
				subGroup2.setParentId(groupOne.getId());
				try (Response res = realmResource.groups().group(groupOne.getId())
					.subGroup(subGroup2)) {
					log.info("Create sub group: " + res.getStatus());
				} catch (Exception ex) {
					log.error("Create sub group failed", ex);
				}
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
					roleDefinitions.add(
						new RolePolicyRepresentation.RoleDefinition(group1Role.getId(), true));
					rolePolicy.setRoles(roleDefinitions);
					try (Response res = clientResource.authorization().policies().role()
						.create(rolePolicy)) {
						log.info("Create role policy: " + res.getStatus());
					} catch (Exception ex) {
						log.error("Create role policy failed", ex);
					}
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
					roleDefinitions.add(
						new RolePolicyRepresentation.RoleDefinition(sub1Role.getId(), true));
					rolePolicy.setRoles(roleDefinitions);
					try (Response res = clientResource.authorization().policies().role()
						.create(rolePolicy)) {
						log.info("Create policy: " + res.getStatus());
					} catch (Exception ex) {
						log.error("Create policy failed", ex);
					}
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
					roleDefinitions.add(
						new RolePolicyRepresentation.RoleDefinition(sub2Role.getId(), true));
					rolePolicy.setRoles(roleDefinitions);
					try (Response res = clientResource.authorization().policies().role()
						.create(rolePolicy)) {
						log.info("Create policy: " + res.getStatus());
					} catch (Exception ex) {
						log.error("Create policy failed", ex);
					}
				});
		
		return ResponseEntity.ok(true);
	}
	
	@PutMapping
	public ResponseEntity<Object> updatePermission(@RequestBody KeycloakUpdatePerRequest request) {
		String username = buildCurrentUserName();
		String userId = getKeycloakIdByUser(username);
		
		List<KeycloakUpdatePerItem> items = request.getItems();
		items = preprocessExistPermission(items);
		
		ClientResource clientResource = keycloakInstance.getClientResource();
		// get permission by resource and scope
		for (KeycloakUpdatePerItem item : items) {
			List<PolicyRepresentation> permissions = clientResource.authorization()
				.policies()
				.policies(null, null, null, item.getResourceId(), item.getScopeId(),
					null, null, null, null, null);
			String perId = permissions.stream()
				.filter(p -> StringUtils.hasText(p.getName()) && !p.getName().contains(NEGATIVE))
				.findFirst().map(PolicyRepresentation::getId)
				.orElse(null);
			item.setPermissionId(perId);
			String negPerId = permissions.stream()
				.filter(p -> StringUtils.hasText(p.getName()) && p.getName().contains(NEGATIVE))
				.findFirst().map(PolicyRepresentation::getId)
				.orElse(null);
			item.setNegativePermissionId(negPerId);
		}
		
		// get user positive policy
		String policyId;
		String polName = POLICY_PREFIX + username;
		UserPolicyRepresentation userPolicy = clientResource.authorization()
			.policies().user().findByName(polName);
		if (userPolicy == null) { // create positive policy
			Set<String> userIds = new HashSet<>(List.of(userId));
			policyId = createUserPolicy(clientResource, polName, userIds, Logic.POSITIVE);
		} else {
			policyId = userPolicy.getId();
		}
		// get user negative policy
		String negativePolicyId;
		String negativePolName = POLICY_PREFIX + username + "::negative";
		UserPolicyRepresentation userNegativePolicy = clientResource.authorization()
			.policies().user().findByName(negativePolName);
		if (userNegativePolicy == null) { // create negative policy
			Set<String> userIds = new HashSet<>(List.of(userId));
			negativePolicyId =
				createUserPolicy(clientResource, negativePolName, userIds, Logic.NEGATIVE);
		} else {
			negativePolicyId = userNegativePolicy.getId();
		}
		
		// permit action
		List<KeycloakUpdatePerItem> permitItems =
			items.stream().filter(s -> PERMIT.equals(s.getStatus())).toList();
		// assign policy to permission
		// remove negative policy from negative permission
		for (KeycloakUpdatePerItem permitItem : permitItems) {
			updatePermissionAssociatedWithPolicy(clientResource, policyId,
				permitItem.getPermissionId(), null);
			updatePermissionAssociatedWithPolicy(clientResource, negativePolicyId, null,
				permitItem.getNegativePermissionId());
		}
		
		// deny action
		List<KeycloakUpdatePerItem> denyItems =
			items.stream().filter(s -> DENY.equals(s.getStatus())).toList();
		// assign negative policy to negative permission
		// remove policy from permission
		for (KeycloakUpdatePerItem permitItem : denyItems) {
			updatePermissionAssociatedWithPolicy(clientResource, negativePolicyId,
				permitItem.getNegativePermissionId(), null);
			updatePermissionAssociatedWithPolicy(clientResource, policyId, null,
				permitItem.getPermissionId());
			
		}
		return ResponseEntity.ok(true);
	}
	
	private List<KeycloakUpdatePerItem> preprocessExistPermission(
		List<KeycloakUpdatePerItem> items) {
		ResponseEntity<Object> permissionList = permissionList();
		if (permissionList == null) {
			return Collections.emptyList();
		}
		KeycloakResponse keycloakResponse = (KeycloakResponse) Objects.requireNonNull(
			permissionList.getBody());
		List<KeycloakResource> keycloakResources = keycloakResponse.getResources();
		
		// remove already assigned permissions
		return items
			.stream()
			.filter(r -> StringUtils.hasText(r.getResourceId())
				&& StringUtils.hasText(r.getScopeId())
				&& StringUtils.hasText(r.getStatus())
				&& allowedStatuses.contains(r.getStatus()))
			.filter(s -> keycloakResources.stream()
				.noneMatch(r -> r.getId().equals(s.getResourceId())
					&& r.getScopes()
					.stream()
					.anyMatch(sc -> sc.getId().equals(s.getScopeId())
						&& sc.getStatus().equals(s.getStatus()))))
			.toList();
	}
	
	private String createUserPolicy(ClientResource clientResource,
	                                String policyName,
	                                Set<String> userIds,
	                                Logic logic) {
		UserPolicyRepresentation createPolicy = new UserPolicyRepresentation();
		createPolicy.setName(policyName);
		createPolicy.setLogic(logic);
		createPolicy.setUsers(userIds);
		try (Response createRes =
			     clientResource.authorization().policies().user().create(createPolicy)) {
			if (createRes.getStatus() != 201) {
				log.error("Create user policy failed");
			}
		} catch (Exception ex) {
			log.error("Create user policy failed", ex);
		}
		UserPolicyRepresentation res =
			clientResource.authorization().policies().user().findByName(policyName);
		return res != null ? res.getId() : null;
	}
	
	private String buildCurrentUserName() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		Jwt jwt = (Jwt) authentication.getPrincipal();
		return jwt.getClaim(PREFERRED_USERNAME);
	}
}

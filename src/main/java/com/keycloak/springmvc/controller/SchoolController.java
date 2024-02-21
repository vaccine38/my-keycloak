package com.keycloak.springmvc.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping(
	value = "/schools",
	produces = MediaType.APPLICATION_JSON_VALUE
)
public class SchoolController {
	
	@GetMapping("/summary")
	public ResponseEntity<String> summary() {
		return ResponseEntity.ok("""
			Posts and Telecommunications Institute of Technology (PTIT) is a national public university within the Vietnam Ministry of Information and Communications (MIC). PTIT has been carrying out the mission to develop the Institute in line with advanced university models in the word by means of highly effective management and organization systems. PTIT is transforming itself to become the highly innovative university in the era of industry 4.0 and digital economy. On the basis of reasonable and effective use of resources, PTIT strives to improve the quality of training and scientific research at the Institute, meeting demands of high-quality human resources in the information and communication sector and ensuring opportunities for the poor and policy beneficiaries to study in PTIT.
			To achieve this goal, we will constantly improve the teaching and research quality through expanding the scope of research and training, strengthening cooperation with domestic and international organizations. PTIT commits to further develop the advancement of knowledge in Vietnam with dedicated and inspired professional staff who are prepared for international integration. We are committed to global engagement with our friends and colleagues from around the world and invite you to PTIT to experience the excitement and creativity of Vietnam with the warmth and hospitality of our people.
			Prof. Dang Hoai Bac – President of PTIT
			""");
	}
}

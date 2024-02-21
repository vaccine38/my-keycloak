package com.keycloak.springmvc.controller;

import com.keycloak.springmvc.dto.BookCreateRequest;
import com.keycloak.springmvc.dto.BookListRequest;
import com.keycloak.springmvc.dto.BookUpdateRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping(
	value = "/students",
	produces = MediaType.APPLICATION_JSON_VALUE
)
public class StudentController {
	
	@GetMapping("/list")
	public ResponseEntity<String> list(@RequestBody BookListRequest request) {
		return ResponseEntity.ok("list student with name keyword " + request.getNameKeyword());
	}
	
	@GetMapping("/{id}")
	public ResponseEntity<String> detail(@PathVariable String id) {
		return ResponseEntity.ok("Student with id " + id);
	}
	
	@PutMapping
	public ResponseEntity<String> update(@RequestBody BookUpdateRequest request) {
		return ResponseEntity.ok("Update student with id " + request.getId() + " updated");
	}
	
	@PostMapping
	public ResponseEntity<String> create(@RequestBody BookCreateRequest request) {
		return ResponseEntity.ok("Create new student with name " + request.getName());
	}
	
	@DeleteMapping("/{id}")
	public ResponseEntity<String> delete(@PathVariable String id) {
		return ResponseEntity.ok("Delete student with id " + id);
	}
}

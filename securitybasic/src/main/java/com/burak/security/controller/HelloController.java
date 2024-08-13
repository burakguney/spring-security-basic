package com.burak.security.controller;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;


@RestController
@RequestMapping("/api/hello")
public class HelloController {

	@GetMapping()
	public String hello() {
		return "Welcome To Burak";
	}
	
}

package com.security.jwt.restcontroller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WelcomeRestController {

	@GetMapping("/welcome")
	public String welcome() {
		return "Welocme to Spring Secuirty With JWT!!!";
	}
	
	
	
	
	
	
}

package com.cos.security1.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;

@Controller
public class IndexController {
	
	@Autowired
	private UserRepository userRepository;
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	//localhost:8080/
	@GetMapping({"","/"})
	public String index() {
		//머스테치 기본폴더 src/main/resource
		//뷰리졸버 설정 : templates(prefix), .mustache(suffix)
		return "index";
	}
	
	//
	@GetMapping("/user")
	public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
		System.out.println("PrincipalDetails : " + principalDetails.getUser());
		return "user";
	}
	@GetMapping("/admin")
	public @ResponseBody String admin() {
		return "admin";
	}
	@GetMapping("/manager")
	public @ResponseBody String manager() {
		return "manager";
	}
	
	
	@GetMapping("/loginForm")
	public String loginForm() {
		return "loginForm";
	}
	@PostMapping("/join")
	public String join(User user) {
		System.out.println(user);
		user.setRole("ROLE_USER");
		String rawPassword = user.getPassword();
		String encPassword = bCryptPasswordEncoder.encode(rawPassword);
		user.setPassword(encPassword);
		userRepository.save(user);
		return "redirect:/loginForm";
	}
	@GetMapping("/joinForm")
	public  String joinForm() {
		return "joinForm";
	}
	
	@Secured("ROLE_ADMIN") //하나의 권한을 간단하게 처리
	@GetMapping("/info")
	public @ResponseBody String info() {
		return "info";
	}
	@PreAuthorize("hasRole('ROLE_MANAGER')or hasRole('ROLE_ADMIN')") //여러 권한을 간단하게 처리
	@GetMapping("/data")
	public @ResponseBody String data() {
		return "data";
	}
	@GetMapping("/test/login")
	public @ResponseBody String testLogin(
			Authentication authentication,
			@AuthenticationPrincipal PrincipalDetails userDetails) {
		System.out.println("/test/login=============");
		PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
		System.out.println("authentication : " + principalDetails.getUser());
		System.out.println("userDetails : " + userDetails.getUser());
		return "세션 정보 확인";
	}
	@GetMapping("/test/oauth/login")
	public @ResponseBody String testOAuthLogin( 
			Authentication authentication,
			@AuthenticationPrincipal OAuth2User oauth) {
		System.out.println("/test/oauth/login=============");
		OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
		System.out.println("authentication : " + oAuth2User.getAttributes());
		System.out.println("oauth2User : " + oauth.getAttributes());
		return "세션 정보 확인";
	}
}

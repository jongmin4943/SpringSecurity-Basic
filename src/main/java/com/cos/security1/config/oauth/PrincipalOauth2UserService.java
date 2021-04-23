package com.cos.security1.config.oauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.config.oauth.provider.GoogleUserInfo;
import com.cos.security1.config.oauth.provider.OAuth2UserInfo;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {
	
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@Autowired
	private UserRepository userRepository;
	
	//구글로 부터 받은 userRequest 데이터에 대한 후처리 되는 함수
	// 함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다
	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
//		System.out.println("getClientRegistration  : " + userRequest.getClientRegistration()); 
//		System.out.println("getAccessToken  : " + userRequest.getAccessToken().getTokenValue());
		//구글 로그인 버튼 클릭->로그인진행->code를 리턴(OAuth-client라이브러리가 처리) ->AccessToken요청
		//loadUser함수로 회원프로필을 받을수있다.
		
		OAuth2User auth2User = super.loadUser(userRequest);
		//System.out.println("getAttributes  : " + auth2User.getAttributes());
		OAuth2UserInfo oAuth2UserInfo = null;
		if(userRequest.getClientRegistration().getRegistrationId().equals("google")) {
			System.out.println("구글 로그인 요청");
			oAuth2UserInfo = new GoogleUserInfo(auth2User.getAttributes());
		} else {
			System.out.println("우리는 구글만 지원해요 ㅎ");
		}
		
//		String provider = userRequest.getClientRegistration().getRegistrationId();// google
//		String providerId = auth2User.getAttribute("sub");
//		String username = provider+"_"+providerId;
//		String password = bCryptPasswordEncoder.encode("겟인데어");
//		String email = auth2User.getAttribute("email");
//		String role = "RORL_USER";
		String provider = oAuth2UserInfo.getProvider();// google
		String providerId = oAuth2UserInfo.getProviderId();
		String username = provider+"_"+providerId;
		String password = bCryptPasswordEncoder.encode("겟인데어");
		String email = oAuth2UserInfo.getEmail();
		String role = "ROLE_USER";
		
		User userEntity = userRepository.findByUsername(username);
		
		if(userEntity == null) {
			
			System.out.println("최초 소셜 로그인");
			userEntity = User.builder()
					.username(username)
					.password(password)
					.email(email)
					.role(role)
					.provider(provider)
					.providerId(providerId)
					.build();
			userRepository.save(userEntity);
		} {
			System.out.println("소셜 로그인 한적이 있음");
		}
		
		return new PrincipalDetails(userEntity,auth2User.getAttributes());
	}
}

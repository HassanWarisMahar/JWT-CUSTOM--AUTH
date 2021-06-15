package com.example.jwt.payload.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
public class JwtResponse {


	private String token;
	private String type = "Bearer";
	private Long id;
	private String username;
	private String email;
	private List<String> roles;
	private String refreshToken;


	public JwtResponse(String token, Long id, String username, String email, List<String> roles) {
		this.token = token;
		this.id = id;
		this.username = username;
		this.email = email;
		this.roles = roles;
	}

	public JwtResponse(String token , Long id , String username, String email, List<String> roles, String refreshToken){

		this.token = token;
		this.id = id;
		this.username = username;
		this.email = email;
		this.roles = roles;
		this.refreshToken=refreshToken;
	}

//	public String getAccessToken() {
//		return token;
//	}
//
//	public void setAccessToken(String accessToken) {
//		this.token = accessToken;
//	}
//
//	public String getTokenType() {
//		return type;
//	}
//
//	public void setTokenType(String tokenType) {
//		this.type = tokenType;
//	}
//
//	public Long getId() {
//		return id;
//	}
//
//	public void setId(Long id) {
//		this.id = id;
//	}
//
//	public String getEmail() {
//		return email;
//	}
//
//	public void setEmail(String email) {
//		this.email = email;
//	}
//
//	public String getUsername() {
//		return username;
//	}
//
//	public void setUsername(String username) {
//		this.username = username;
//	}
//
//	public List<String> getRoles() {
//		return roles;
//	}
}
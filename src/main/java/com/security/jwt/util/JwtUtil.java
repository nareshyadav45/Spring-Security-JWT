package com.security.jwt.util;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtUtil {

	private String SECRET_KEY = "secret";

	public Claims extratAllClaims(String token) {
		return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
	}

	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		Claims extratAllClaims = extratAllClaims(token);
		return claimsResolver.apply(extratAllClaims);
	}

	public String extractUsername(String token) {
		String userName = extractClaim(token, Claims::getSubject);
		return userName;
	}

	public Date extractTokenExpiration(String token) {
		Date dateOfTokenExpiration = extractClaim(token, Claims::getExpiration);
		return dateOfTokenExpiration;
	}

	public Boolean isTokenExpired(String token) {
		boolean isTokenExpired = extractTokenExpiration(token).before(new Date());
		return isTokenExpired;
	}

	public String createToken(Map<String, Object> claims, String subject) {
		return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
				//set the token expiration about 1HOUR
				//.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 1))
				.setExpiration(new Date(System.currentTimeMillis() + 2 * 60 * 1000))
				.signWith(SignatureAlgorithm.HS256, SECRET_KEY).compact();
	}

	public String generateToken(UserDetails userDetails) {
		Map<String, Object> claims = new HashMap<>();
		String token = createToken(claims, userDetails.getUsername());
		return token;

	}
	
	public Boolean validateToken(String token,UserDetails details) {
		String username = extractUsername(token);
		return (username.equals(details.getUsername())&& !isTokenExpired(token));
	}
	
}

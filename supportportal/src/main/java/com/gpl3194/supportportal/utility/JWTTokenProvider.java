package com.gpl3194.supportportal.utility;

import java.util.Date;

import org.springframework.beans.factory.annotation.Value;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import static com.gpl3194.supportportal.constant.SecurityConstant.*;
import com.gpl3194.supportportal.domain.UserPrincipal;

public class JWTTokenProvider {
	
	@Value("jwt.secret")
	private String secret;
	
	public String generateJwtToken(UserPrincipal userPrincipal) {
		
		String[] claims = getClaimsFromUser(userPrincipal);
		
		return JWT.create().withIssuer(GET_ARRAYS_LLC).withAudience(GET_ARRAYS_ADMINISTRATION)
				.withIssuedAt(new Date()).withSubject(userPrincipal.getUsername())
				.withArrayClaim(AUTHORITIES, claims).withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
				.sign(Algorithm.HMAC512(secret.getBytes()));
	}

	private String[] getClaimsFromUser(UserPrincipal userPrincipal) {
	
		return null;
	}

}

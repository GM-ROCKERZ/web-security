package com.gpl3194.supportportal.utility;

import static com.gpl3194.supportportal.constant.SecurityConstant.AUTHORITIES;
import static com.gpl3194.supportportal.constant.SecurityConstant.EXPIRATION_TIME;
import static com.gpl3194.supportportal.constant.SecurityConstant.GET_ARRAYS_ADMINISTRATION;
import static com.gpl3194.supportportal.constant.SecurityConstant.GET_ARRAYS_LLC;
import static com.gpl3194.supportportal.constant.SecurityConstant.TOKEN_CANNOT_BE_VERIFIED;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.gpl3194.supportportal.domain.UserPrincipal;

public class JWTTokenProvider {
	
	@Value("${jwt.secret}")
	private String secret;
	
	public String generateJwtToken(UserPrincipal userPrincipal) {
		
		String[] claims = getClaimsFromUser(userPrincipal);
		
		return JWT.create().withIssuer(GET_ARRAYS_LLC).withAudience(GET_ARRAYS_ADMINISTRATION)
				.withIssuedAt(new Date()).withSubject(userPrincipal.getUsername())
				.withArrayClaim(AUTHORITIES, claims).withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
				.sign(Algorithm.HMAC512(secret.getBytes()));
	}

	  public List<GrantedAuthority> getAuthorities(String token) {
	        String[] claims = getClaimsFromToken(token);
	        return stream(claims).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
	    }
	
	private String[] getClaimsFromToken(String token) {
		
		JWTVerifier verifier = getJWTVerifier();
		
		return verifier.verify(token).getClaim(AUTHORITIES).asArray(String.class);
	}


    private JWTVerifier getJWTVerifier() {
        JWTVerifier verifier;
        try {
            Algorithm algorithm = HMAC512(secret);
            verifier = JWT.require(algorithm).withIssuer(GET_ARRAYS_LLC).build();
        }catch (JWTVerificationException exception) {
            throw new JWTVerificationException(TOKEN_CANNOT_BE_VERIFIED);
        }
        return verifier;
    }

	private String[] getClaimsFromUser(UserPrincipal user) {
	
		List<String> authorties =new ArrayList<>();
		
		for(GrantedAuthority grantedAuthority:user.getAuthorities()) {
			
			authorties.add(grantedAuthority.getAuthority());
		}
		
		return authorties.toArray(new String[0]);
	}

}

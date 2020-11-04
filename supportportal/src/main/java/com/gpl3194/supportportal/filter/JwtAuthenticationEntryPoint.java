package com.gpl3194.supportportal.filter;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import java.io.IOException;
import java.io.OutputStream;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gpl3194.supportportal.constant.SecurityConstant;
import com.gpl3194.supportportal.domain.HttpResponse;

public class JwtAuthenticationEntryPoint extends Http403ForbiddenEntryPoint{

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException {
		
		HttpResponse httpResponse = new HttpResponse(HttpStatus.FORBIDDEN.value(),HttpStatus.FORBIDDEN,HttpStatus.FORBIDDEN.getReasonPhrase().toUpperCase(),SecurityConstant.FORBIDDEN_MESSAGE);
		
		
		response.setContentType(APPLICATION_JSON_VALUE);
		response.setStatus(HttpStatus.FORBIDDEN.value());
		OutputStream outputstream = response.getOutputStream();
		
		ObjectMapper mapper = new ObjectMapper();
		mapper.writeValue(outputstream, httpResponse);
		outputstream.flush();
		
	}

}

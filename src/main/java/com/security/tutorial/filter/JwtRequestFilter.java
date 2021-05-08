package com.security.tutorial.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.security.tutorial.JwtTokenUtil;
import com.security.tutorial.service.JwtUserDetailsService;
import com.sun.net.httpserver.Filter.Chain;

import io.jsonwebtoken.ExpiredJwtException;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {
	
	@Autowired
	private JwtUserDetailsService userDetailServ;
	
	@Autowired
	private JwtTokenUtil jwtTokenUtil;
	Log log = LogFactory.getLog(JwtRequestFilter.class);

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		
		final String requestAuthHeader = request.getHeader("Authorization");
		
		String username = null;
		String token = null;
		
		// Authorization: Bearer <token>
		
		if(requestAuthHeader != null && requestAuthHeader.startsWith("Bearer")) {
			token = requestAuthHeader.substring(7);
			try {
				username = jwtTokenUtil.getUserNameFromToken(token);
				
			} catch(IllegalArgumentException e) {
				log.error("Unable to get JWT token");
			} catch(ExpiredJwtException e) {
				log.error("JWT token expired");
			}
		} else {
			log.warn("JWT doesn't start with bearer");
		}
		
		// validate token
		log.info(username);
		log.info(SecurityContextHolder.getContext().getAuthentication());
		if(username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
			UserDetails userDetails = this.userDetailServ.loadUserByUsername(username);
			// if token is valid configure security to set manually the authentication
			if(jwtTokenUtil.validateToken(token, userDetails)) {
				UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
				usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				// After setting Authentication in context, we specify that current user is authenticated n pass all security configs
				SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
			}
		}
		filterChain.doFilter(request, response);
		
	}
	
	
}

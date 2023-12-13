package com.example.apiBook.util;


import com.example.apiBook.entity.User;
import com.example.apiBook.security.service.UserDetailsImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.stream.Collectors;

public final class UserUtil {

	static final Logger logger = LoggerFactory.getLogger(UserUtil.class);

	public static Authentication getAuth() {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		return auth;
	}

	public static UserDetailsImpl getPrincipal() {
		Authentication auth = getAuth();
		if (auth != null) {
			Object u = auth.getPrincipal();
			if (u instanceof UserDetailsImpl || u instanceof User) {
				return (UserDetailsImpl) auth.getPrincipal();
			}
		}
		return null;
	}

	public static Long getUserId() {
		User u = getCurrentUser();
		if (u != null) {
			return u.getId();
		}
		return null;
	}

	public static String getUsername() {
		User u = getCurrentUser();
		if (u != null) {
			return u.getUsername();
		}
		return "";
	}
	public static String getName() {
		User u = getCurrentUser();
		String name = "";
		if (u != null) {
			name = u.getFirstName() + u.getLastName();
		}
		return name;
	}

	public static List<String> getUserRoles() {
		Authentication au = getAuth();
		if (au == null)
			return null;

		return au.getAuthorities().stream().map(r -> r.getAuthority()).collect(Collectors.toList());
	}
	
	public static User getCurrentUser() {
		return getPrincipal();
	}
}

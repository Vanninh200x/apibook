package com.example.apiBook.commons;


import java.util.Map;

public enum RoleEnum {
    ADMIN("ROLE_ADMIN"),
    USER("ROLE_USER"),
    AUTHOR("ROLE_AUTHOR");

    private static Map<String, RoleEnum> map;

    private final String role;

    public String getRole() {
        return role;
    }

    RoleEnum(final String role) {
        this.role = role;
    }

    public static RoleEnum getRole(String name) {
        if(map != null) {
            return map.get(name);
        }
        for (RoleEnum r : RoleEnum.values()) {
            map.put(r.getRole(), r);
        }
        return map.get(name);
    }
}

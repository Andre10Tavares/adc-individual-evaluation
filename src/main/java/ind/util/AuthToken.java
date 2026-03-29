package ind.util;

import java.util.UUID;

public class AuthToken {

    public static final long EXPIRATION_TIME = 900;
    public String tokenId;
    public String username;
    public String role;
    public long issuedAt;
    public long expiresAt;

    public AuthToken(){}

    public AuthToken(String username, String role){
        this.tokenId = UUID.randomUUID().toString();
        this.username = username;
        this.role = role;
        this.issuedAt = System.currentTimeMillis() / 1000;
        this.expiresAt = this.issuedAt + EXPIRATION_TIME;
    }

    public AuthToken(String tokenId, String  username, String role, long issuedAt, long expiresAt) {
        this.tokenId = tokenId;
        this.username = username;
        this.role = role;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
    }

    private boolean nonEmptyOrBlankField(String field) {
        return field != null && !field.isBlank();
    }

    public boolean validTokenInput() {
        return nonEmptyOrBlankField(tokenId) &&
                nonEmptyOrBlankField(username) &&
                nonEmptyOrBlankField(role) &&
                (role.equalsIgnoreCase("USER") || role.equalsIgnoreCase("BOFFICER") || role.equalsIgnoreCase("ADMIN")) &&
                username.contains("@");
    }
}

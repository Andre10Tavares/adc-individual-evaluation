package ind.util;

import java.util.UUID;

public class TokenData {

    public static final long EXPIRATION_TIME = 900;
    public String tokenId;
    public String username;
    public String role;
    public long issuedAt;
    public long expiresAt;

    public TokenData(){}

    public TokenData(String username, String role){
        this.tokenId = UUID.randomUUID().toString();
        this.username = username;
        this.role = role;
        this.issuedAt = System.currentTimeMillis() / 1000;
        this.expiresAt = this.issuedAt + EXPIRATION_TIME;
    }
}

package ind.util;

public class SessionInfo {

    public String tokenId;
    public String username;
    public String role;
    public long experesAt;

    public SessionInfo(){}

    public SessionInfo(String tokenId, String username, String role, long experesAt){
        this.tokenId = tokenId;
        this.username = username;
        this.role = role;
        this.experesAt = experesAt;
    }
}

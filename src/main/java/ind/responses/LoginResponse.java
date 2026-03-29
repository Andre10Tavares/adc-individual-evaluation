package ind.responses;

import ind.util.AuthToken;

public class LoginResponse {
    public AuthToken token;

    public LoginResponse(){}

    public LoginResponse(AuthToken token) {
        this.token = token;
    }
}

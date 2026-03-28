package ind.responses;

public class CreateAccountResponse {

    public String username;
    public String role;

    public CreateAccountResponse(){}

    public CreateAccountResponse(String username, String role) {
        this.username = username;
        this.role = role;
    }
}

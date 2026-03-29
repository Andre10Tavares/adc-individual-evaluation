package ind.util;

public class AuthData {
    public InputData input;
    public AuthToken token;

    public AuthData() {}

    public AuthData(InputData input, AuthToken token) {
        this.input = input;
        this.token = token;
    }
}

package ind.util.StringMessages;

public class ErrorMessages {
    public static final String INVALID_CREDENTIALS = "The username-password pair is not valid";
    public static final String USER_ALREADY_EXISTS = "Error in creating an account because the username already exists";
    public static final String USER_NOT_FOUND = "The username referred in the operation doesn’t exist in registered accounts";
    public static final String INVALID_TOKEN = "The operation is called with an invalid token (wrong format for example)";
    public static final String TOKEN_EXPIRED = "The operation is called with a token that is expired";
    public static final String UNAUTHORIZED = "The operation is not allowed for the user role";
    public static final String INVALID_INPUT = "The call is using input data not following the correct specification";
    public static final String FORBIDDEN = "The operation generated a forbidden error by other reason";

    public static final int ERROR_INVALID_CREDENTIALS = 9900;
    public static final int ERROR_USER_ALREADY_EXISTS = 9901;
    public static final int ERROR_USER_NOT_FOUND = 9902;
    public static final int ERROR_INVALID_TOKEN = 9903;
    public static final int ERROR_TOKEN_EXPIRED = 9904;
    public static final int ERROR_UNAUTHORIZED = 9905;
    public static final int ERROR_INVALID_INPUT = 9906;
    public static final int ERROR_FORBIDDEN = 9907;
}

package ind.util;

public class CreateAccountData {
    public String username;
    public String password;
    public String confirmation;
    public String phone;
    public String address;
    public String role;

    public CreateAccountData() {}

    public CreateAccountData(String username, String password, String confirmation, String phone, String address, String role) {
        this.username = username;
        this.password = password;
        this.confirmation = confirmation;
        this.phone = phone;
        this.address = address;
        this.role = role;
    }

    private boolean nonEmptyOrBlankField(String field) {
        return field != null && !field.isBlank();
    }

    public boolean validRegistration() {
        return nonEmptyOrBlankField(username) &&
                nonEmptyOrBlankField(password) &&
                nonEmptyOrBlankField(confirmation) &&
                nonEmptyOrBlankField(phone) &&
                nonEmptyOrBlankField(address) &&
                nonEmptyOrBlankField(role) &&
                username.contains("@") &&
                password.equals(confirmation) &&
                (role.equalsIgnoreCase("USER") || role.equalsIgnoreCase("BOFFICER") || role.equalsIgnoreCase("ADMIN"));
    }
}

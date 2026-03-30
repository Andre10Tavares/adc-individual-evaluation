package ind.util;

public class InputData {

    public String username;
    public AttributesData attributes;
    public String newRole;
    public String oldPassword;
    public String newPassword;

    //Arranjar maneira melhor depois ------------------
    public String password;
    public String confirmation;
    public String phone;
    public String address;
    public String role;

    public InputData(String username, String password, String confirmation, String phone, String address, String role) {
        this.username = username;
        this.password = password;
        this.confirmation = confirmation;
        this.phone = phone;
        this.address = address;
        this.role = role;
    }

    //--------------------------------------------------

    public InputData() {}

    public InputData(String username) {
        this.username = username;
    }

    public InputData(String username, AttributesData attributes) {
        this.username = username;
        this.attributes = attributes;
    }

    public InputData(String username, String newRole) {
        this.username = username;
        this.newRole = newRole;
    }

    public InputData(String username, String oldPassword, String newPassword) {
        this.username = username;
        this.oldPassword = oldPassword;
        this.newPassword = newPassword;
    }

    private boolean nonEmptyOrBlankField(String field) {
        return field != null && !field.isBlank();
    }

    //Only username in Ops 4, 7, 10.
    //All the other validations use this one
    public boolean validUsername() {
        return nonEmptyOrBlankField(username) &&
                username.contains("@");
    }

    //Used in Op 5
    public boolean validAttributes() {
        return validUsername() &&
                attributes.validAttributes();
    }

    //Used in Op 8
    public boolean validRole() {
        return nonEmptyOrBlankField(newRole) &&
                (newRole.equalsIgnoreCase("USER") ||
                        newRole.equalsIgnoreCase("BOFFICER") ||
                        newRole.equalsIgnoreCase("ADMIN"));
    }

    //Used in Op 9
    public boolean validPasswordInput() {
        return validUsername() &&
                nonEmptyOrBlankField(newPassword) &&
                nonEmptyOrBlankField(oldPassword);
    }
}

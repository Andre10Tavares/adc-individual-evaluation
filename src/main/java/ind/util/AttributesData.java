package ind.util;

public class AttributesData {
    public String phone;
    public String address;

    public AttributesData(){}

    public AttributesData(String phone, String address) {
        this.phone = phone;
        this.address = address;
    }

    private boolean nonEmptyOrBlankField(String field) {
        return field != null && !field.isBlank();
    }

    public boolean validAttributes() {
        return nonEmptyOrBlankField(phone) &&
                nonEmptyOrBlankField(address);
    }
}

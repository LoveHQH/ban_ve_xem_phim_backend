package mflix.api.models;

public class Person {
    private String first_name;
    private String last_name;
    private String email;
    private String phone_number;

    public String getFirstName() {
        return first_name;
    }

    public void setFirstName(String firstName) {
        this.first_name = firstName;
    }

    public String getLast_name() {
        return last_name;
    }

    public void setLast_name(String last_name) {
        this.last_name = last_name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPhone_number() {
        return phone_number;
    }

    public void setPhone_number(String phone_number) {
        this.phone_number = phone_number;
    }

    @Override
    public String toString() {
        return "Person{"
                + "firstName='"
                + first_name
                + '\''
                + ", lastName='"
                + last_name
                + '\''
                + ", email='"
                + email
                + '\''
                + ", phoneNumber='"
                + phone_number
                + '\''
                + '}';
    }
}

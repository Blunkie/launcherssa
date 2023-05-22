package runelite;

import java.io.Serializable;

public class ProxyProfile implements Serializable {

    private String address;
    private int port;
    private String user;
    private String password;

    public ProxyProfile(String address, int port, String user, String password) {
        this.address = address;
        this.port = port;
        this.user = user;
        this.password = password;
    }

    public String getAddress() {
        return address;
    }

    public int getPort() {
        return port;
    }

    public String getUser() {
        return user;
    }

    public String getPassword() {
        return password;
    }

    @Override
    public String toString() {
        return address + ":" + port;
    }
}

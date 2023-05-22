package runelite;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;

public class IPAddressLogger {
    private static final String FILE_PATH = "ip_address.txt";
    private static final String IP_API_URL = "https://api.ipify.org";


    public static String getPublicIPAddress() {
        StringBuilder ipAddress = new StringBuilder();
        try {
            URL url = new URL(IP_API_URL);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);

            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                InputStream inputStream = connection.getInputStream();
                BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
                String line;
                while ((line = reader.readLine()) != null) {
                    ipAddress.append(line);
                }
                reader.close();
            } else {
                System.out.println("Failed to retrieve IP address. Response code: " + responseCode);
            }

            connection.disconnect();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return ipAddress.toString();
    }

    public static void writeToFile(String text) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(FILE_PATH))) {
            writer.write(text);
            System.out.println("IP Address written to file: " + FILE_PATH);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

package projeto;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import javax.crypto.Cipher;

public class mySNS {

    public static void main(String[] args) throws InterruptedException {
        if (args.length < 4 || !args[0].equals("-a") || !args[2].equals("-m") || !args[4].equals("-u")) {
            System.out.println("Usage: java mySNS -a <serverAddress> -m <doctorUsername> -u <userUsername> [-sc <filenames>] [-sa <filenames>] [-se <filenames>] [-g <filenames>]");
            return;
        }

        String serverAddress = args[1];
        String[] addressParts = serverAddress.split(":");
        if (addressParts.length != 2) {
            System.out.println("Invalid server address format. Use the format: hostname:port");
            return;
        }

        String hostname = addressParts[0];
        int port;
        try {
            port = Integer.parseInt(addressParts[1]);
        } catch (NumberFormatException e) {
            System.out.println("Port must be an integer.");
            return;
        }

        String doctorUsername = args[3];
        String userUsername = args[5];

        // Verify if the doctor's alias exists in the keystore.medico
        try {
            FileInputStream kfileDoctor = new FileInputStream("keystore.medico");
            KeyStore kstoreDoctor = KeyStore.getInstance("PKCS12");
            kstoreDoctor.load(kfileDoctor, "123456".toCharArray()); // Provide the correct keystore password

            if (!kstoreDoctor.containsAlias(doctorUsername)) {
                System.out.println("Doctor username '" + doctorUsername + "' does not exist in the keystore.medico.");
                return;
            }
            System.out.println("Doctor alias verified in keystore.medico.");
        } catch (Exception e) {
            System.err.println("Error loading keystore.medico: " + e.getMessage());
            return;
        }

        // Verify if the user's alias exists in the keystore.utente
        try {
            FileInputStream kfileUser = new FileInputStream("keystore.utente");
            KeyStore kstoreUser = KeyStore.getInstance("PKCS12");
            kstoreUser.load(kfileUser, "123456".toCharArray()); // Provide the correct keystore password

            if (!kstoreUser.containsAlias(userUsername)) {
                System.out.println("User username '" + userUsername + "' does not exist in the keystore.utente.");
                return;
            }
            System.out.println("User alias verified in keystore.utente.");
        } catch (Exception e) {
            System.err.println("Error loading keystore.utente: " + e.getMessage());
            return;
        }

        Socket socket = null;
        try {
            System.out.println("Attempting to connect to the server: " + hostname + ":" + port);
            socket = new Socket(hostname, port);
            System.out.println("Connection successful to the server: " + hostname + ":" + port);

            // TODO: Implement logic for other commands provided in the command line arguments

        } catch (UnknownHostException e) {
            System.err.println("Error connecting to the server. Unknown server address: " + hostname);
        } catch (IOException e) {
            System.err.println("Error connecting to the server: " + e.getMessage());
        } finally {
            if (socket != null && !socket.isClosed()) {
                try {
                    System.out.println("Closing connection to the server...");
                    socket.close();
                    System.out.println("Connection closed.");
                } catch (IOException e) {
                    System.err.println("Error closing the connection: " + e.getMessage());
                }
            }
        }
    }
}

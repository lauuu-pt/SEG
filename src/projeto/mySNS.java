package projeto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

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

        // Check for the specified combinations of commands
        if (args.length >= 8) {
            String command = args[6];
            String[] filenames = new String[args.length - 7];
            System.arraycopy(args, 7, filenames, 0, filenames.length);
            switch (command) {
                case "-sc":
                	metodosc(hostname, port, filenames, doctorUsername, userUsername);
                    break;
                case "-sa":
                    // Handle the logic for command -sa
                    break;
                case "-se":
                    // Handle the logic for command -se
                    break;
                default:
                    System.out.println("Invalid command: " + command);
            }
        } else if (args.length >= 6 && args[6].equals("-g")) {
            if (args.length == 7) {
                String[] filenames = args[7].substring(1, args[7].length() - 1).split(",");
                // Handle the logic for command -g
            } else {
                System.out.println("No filenames provided for command -g.");
            }
        } else {
            System.out.println("Invalid combination of commands.");
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

    private static void metodosc(String hostname, int port, String[] filenames, String doctorUsername, String userUsername) {
        try {
            // Connect to the server
            Socket socket = new Socket(hostname, port);
            System.out.println("Connected to the server.");

            // Implement the logic to encrypt and send files to the server
            for (String filename : filenames) {
                // Generate a random AES key
                KeyGenerator kg = KeyGenerator.getInstance("AES");
                kg.init(128);
                SecretKey key = kg.generateKey();

                // Initialize AES cipher
                Cipher c = Cipher.getInstance("AES");
                c.init(Cipher.ENCRYPT_MODE, key);

                // Create input and output streams
                FileInputStream fis = new FileInputStream(filename);
                FileOutputStream fos = new FileOutputStream(filename + ".cifrado");
                CipherOutputStream cos = new CipherOutputStream(fos, c);

                // Encrypt the file
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    cos.write(buffer, 0, bytesRead);
                }

                // Close streams
                fis.close();
                cos.close();

                System.out.println("File encrypted: " + filename + " -> " + filename + ".cifrado");

                // Save the key to a file
                saveKeyToFile(key, filename, userUsername);
                
                //file 1 é enviado par o server por isso é que não aparece <--------------------------------------------------------------
                // Transfer the encrypted file to the server
                FileInputStream encryptedFileInputStream = new FileInputStream(filename + ".cifrado");
                byte[] fileBytes = encryptedFileInputStream.readAllBytes();
                encryptedFileInputStream.close();

                // Send the file bytes to the server
                ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());
                outputStream.writeObject(fileBytes);
                outputStream.flush();
                System.out.println("Encrypted file sent to the server: " + filename + ".cifrado");

                // Clean up temporary files
                new File(filename + ".cifrado").delete();
            }

            // Close the socket
            socket.close();
            System.out.println("Connection closed.");
        } catch (UnknownHostException e) {
            System.err.println("Error connecting to the server. Unknown server address: " + hostname);
        } catch (IOException e) {
            System.err.println("Error connecting to the server: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }

    private static void saveKeyToFile(SecretKey key, String filename, String userUsername) {
        try {
            // Create the filename for the key file
            String keyFilename = filename + ".chave_secreta." + userUsername;

            // Write the key bytes to the key file
            FileOutputStream fos = new FileOutputStream(keyFilename);
            fos.write(key.getEncoded());
            fos.close();

            System.out.println("Key saved to file: " + keyFilename);
        } catch (IOException e) {
            System.err.println("Error saving key to file: " + e.getMessage());
        }
    }

}
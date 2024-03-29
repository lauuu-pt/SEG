package projeto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
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

        

        // Check if the keystore.medico file exists
        File medicoFile = new File("keystore."+ doctorUsername); // Change variable name from medicoKeystore to doctorUsername
        if (!medicoFile.exists()) {
            System.out.println("Keystore do medico " + doctorUsername +" nao existe");
            return;
        }

        // Check if the keystore.utente file exists
        File utenteFile = new File("keystore."+ userUsername);
        if (!utenteFile.exists()) {
            System.out.println("Keystore do utente"+ userUsername +" nao existe.");
            return;
        }

        // Rest of your code using doctorUsername and userUsername


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
    }

        /*Socket socket = null;
        try {
            System.out.println("Attempting to connect to the server: " + hostname + ":" + port);
            socket = new Socket(hostname, port);
            System.out.println("Connection successful to the server: " + hostname + ":" + port);*/

            // TODO: Implement logic for other commands provided in the command line arguments

        /*} catch (UnknownHostException e) {
            System.err.println("Error connecting to the server. Unknown server address: " + hostname);
        } catch (SocketException e) { // Catch SocketException separately
            System.err.println("Error connecting to the server: Connection reset by peer.");
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
    }*/
    

    private static void metodosc(String hostname, int port, String[] filenames, String doctorUsername, String userUsername) {
        try (Socket socket = new Socket(hostname, port)) {
            System.out.println("Connected to the server.");

            // Implement the logic to encrypt and send files to the server
            for (String filename : filenames) {
                // Generate a random AES key
                KeyGenerator kg = KeyGenerator.getInstance("AES");
                kg.init(128);
                SecretKey aesKey = kg.generateKey();
                
                encryptFileWithAES(filename, aesKey);
                encryptAESKeyWithRSA(aesKey, userUsername, filename);
                sendFilesToServer(hostname, port, filenames);


               
                } 
            // The socket will be closed automatically at the end of the try-with-resources block
            System.out.println("Closing connection to the server...");
        } catch (UnknownHostException e) {
            System.err.println("Error connecting to the server. Unknown server address: " + hostname);
        } catch (IOException e) {
            System.err.println("Error connecting to the server: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }


    private static void encryptAESKeyWithRSA(SecretKey aesKey, String userUsername, String filename) throws FileNotFoundException, IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException {
    	try (FileOutputStream kos = new FileOutputStream(filename + ".key")) {
    		FileInputStream kfile = new FileInputStream("keystore."+ userUsername);
    		KeyStore kstore = KeyStore.getInstance("PKCS12");
    		kstore.load(kfile, "123456".toCharArray());           //password
    		Certificate cert = kstore.getCertificate(userUsername);
    		//alias do utilizador
    		Cipher c1=Cipher.getInstance("RSA");
    		c1.init(Cipher.WRAP_MODE,cert);
    		byte[]keyEncoded=c1.wrap(aesKey);


    		
    		kos.write(keyEncoded);
    		kos.close();
    		
    		
    	}
    }

	private static void encryptFileWithAES(String filename, SecretKey aesKey) throws FileNotFoundException, IOException {
    	 try (FileInputStream fis = new FileInputStream(filename);
                 FileOutputStream fos = new FileOutputStream(filename + ".cifrado");
                 CipherOutputStream cos = new CipherOutputStream(fos, getAESCipher(aesKey))) {

                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    cos.write(buffer, 0, bytesRead);
                }
                cos.flush(); 
            }
            System.out.println("File encrypted: " + filename + " -> " + filename + ".cifrado");
		}
    private static Cipher getAESCipher(SecretKey aesKey) throws IOException {
        try {
            Cipher c = Cipher.getInstance("AES");
            c.init(Cipher.ENCRYPT_MODE, aesKey);
            return c;
        } catch (Exception e) {
            throw new IOException("Error initializing AES cipher: " + e.getMessage());
        }
    }
    private static void sendFilesToServer(String hostname, int port, String[] filenames) {
        try (Socket socket = new Socket(hostname, port)) {
            System.out.println("Connected to the server.");

            for (String filename : filenames) {
                // Send each encrypted file to the server
                sendFileToServer(filename, socket);
            }

            System.out.println("All files sent to the server.");
        } catch (UnknownHostException e) {
            System.err.println("Error connecting to the server. Unknown server address: " + hostname);
        } catch (IOException e) {
            System.err.println("Error connecting to the server: " + e.getMessage());
        }
    }

 
    private static void sendFileToServer(String filename, Socket socket) {
        try (FileInputStream fis = new FileInputStream(filename + ".cifrado");
             ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream())) {

            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                outStream.write(buffer, 0, bytesRead);
            }
            outStream.flush(); // Ensure all data is sent

            System.out.println("File sent to the server: " + filename + ".cifrado");
        } catch (FileNotFoundException e) {
            System.err.println("File not found: " + filename + ".cifrado");
        } catch (IOException e) {
            System.err.println("Error sending file to the server: " + e.getMessage());
        }
    }


}
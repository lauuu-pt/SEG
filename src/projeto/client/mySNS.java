package projeto.client;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
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

    private static Socket socket;

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
        File medicoFile = new File("keystore." + doctorUsername);
        if (!medicoFile.exists()) {
            System.out.println("Keystore do medico " + doctorUsername + " nao existe");
            return;
        }

        // Check if the keystore.utente file exists
        File utenteFile = new File("keystore." + userUsername);
        if (!utenteFile.exists()) {
            System.out.println("Keystore do utente" + userUsername + " nao existe.");
            return;
        }

        try {
            // Establish socket connection
            socket = new Socket(hostname, port);
            System.out.println("Connected to the server.");

            // Execute the desired command
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
            }

            // Close the socket after all operations are done
            socket.close();
            System.out.println("Connection closed.");
        } catch (UnknownHostException e) {
            System.err.println("Error connecting to the server. Unknown server address: " + hostname);
        } catch (IOException e) {
            System.err.println("Error connecting to the server: " + e.getMessage());
        }
    }

    private static void metodosc(String hostname, int port, String[] filenames, String doctorUsername, String userUsername) {
        try {
            // Implement the logic to encrypt and send files to the server
            for (String filename : filenames) {
                // Generate a random AES key
                KeyGenerator kg = KeyGenerator.getInstance("AES");
                kg.init(128);
                SecretKey aesKey = kg.generateKey();

                encryptFileWithAES(filename, aesKey);
                encryptAESKeyWithRSA(aesKey, userUsername, filename);
                
            }
            // After encrypting the files, send them to the server
            sendFilesToServer(filenames);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error generating AES key: " + e.getMessage());
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
    private static void sendFilesToServer(String[] filenames) {
        try {
            ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());

            // Send initial data
            outStream.writeObject("aa");
            outStream.writeObject("bb");

            // Send each encrypted file to the server
            for (String filename : filenames) {
                // Send file size to the server
                File myFile = new File(filename);
                Long fileSize = myFile.length();
                outStream.writeObject(fileSize);

                // Send file contents to the server
                try (BufferedInputStream myFileB = new BufferedInputStream(new FileInputStream(filename))) {
                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = myFileB.read(buffer, 0, 1024)) > 0) {
                        outStream.write(buffer, 0, bytesRead);
                    }
                }
            }

            // Send end-of-file indicator to the server
            outStream.writeObject(-1L); // Indicate end of file transfer
            outStream.flush(); // Flush the stream to ensure all data is sent

            // Wait for acknowledgment from the server
            ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());
            Boolean acknowledgment = (Boolean) inStream.readObject();
            System.out.println("Server acknowledgment: " + acknowledgment);

            // Close the socket after receiving acknowledgment
            socket.close();
            System.out.println("Connection closed.");

        } catch (IOException | ClassNotFoundException e) {
            System.err.println("Error sending files to the server: " + e.getMessage());
        }
    }
} 
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
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class mySNS {

    private static Socket socket;

    public static void main(String[] args) throws InterruptedException, ClassNotFoundException {
        if (args.length < 6 || !args[0].equals("-a") ) {
            System.out.println("Usage: java mySNS -a <serverAddress> -m <doctorUsername> -u <userUsername> [-sc <filenames>] [-sa <filenames>] [-se <filenames>] [-g <filenames>]\nou\nUsage: java mySNS -a <serverAddress> -u <username do utente> -g {<filenames>}+");
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

        

        try {
            // Establish socket connection
            socket = new Socket(hostname, port);
            System.out.println("Connected to the server.");
            String userUsername = args[3];
           
            if (args.length >= 6 && args[4].equals("-g")) {
                System.out.println("Vale");
                if (args.length > 6) {
                    String[] filenames = new String[args.length - 5];
                    System.arraycopy(args, 5, filenames, 0, filenames.length);
                    
                    for (String filename : filenames) {
                        System.out.println("Filename: " + filename);
                        getFilesFromServer(new String[] { filename }, userUsername);
                    }
                } else if (args.length == 6) {
                    String filename = args[5];
                    System.out.println("Filename1: " + filename);
                    getFilesFromServer(new String[] { filename }, userUsername);
                } else {
                    System.out.println("No filenames provided.");
                }
            }

            



            // Execute the desired command
            
             else if (args.length >= 8) {
            	 String doctorUsername = args[3];
                 String userUsernamee = args[5];

                 // Check if the keystore.medico file exists
                 File medicoFile = new File("keystore." + doctorUsername);
                 if (!medicoFile.exists()) {
                     System.out.println("Keystore do medico " + doctorUsername + " nao existe");
                     return;
                 }

                 // Check if the keystore.utente file exists
                 File utenteFile = new File("keystore." + userUsernamee);
                 if (!utenteFile.exists()) {
                     System.out.println("Keystore do utente" + userUsernamee + " nao existe.");
                     return;
                 }
                 
                 
                 
                 
                String command = args[6];
                String[] filenames = new String[args.length - 7];
                System.arraycopy(args, 7, filenames, 0, filenames.length);
                switch (command) {
                    case "-sc":
                        metodosc(hostname, port, filenames, doctorUsername, userUsernamee);
                        deleteFiles(filenames, userUsernamee);
                        break;
                    case "-sa":
                        metodosa(hostname, port, filenames, doctorUsername, userUsernamee);
                        break;
                    case "-se":
                        metodose(hostname, port, filenames, doctorUsername, userUsernamee);
                        break;
                    default:
                        System.out.println("Invalid command: " + command);
                }
            } else {
                System.out.println("Invalid command or combination of commands.");
            }


            // Close the socket after all operations are done
            // socket.close();
            // System.out.println("Connection closed.");
        } catch (UnknownHostException e) {
            System.err.println("Error connecting to the server. Unknown server address: " + hostname);
        } catch (IOException e) {
            System.err.println("Error connecting to the server: " + e.getMessage());
        }
    }

    private static void deleteFiles(String[] filenames,String userUsername) {
    	 for (String filename : filenames) {
    	        File cifradoFile = new File(filename + ".cifrado");
    	        File keyFile = new File(filename + ".chave_secreta." + userUsername);

    	        if (cifradoFile.exists()) {
    	            cifradoFile.delete();
    	            
    	        }
    	        if (keyFile.exists()) {
    	            keyFile.delete();
    	            
    	        }
    	    }
	}

    private static void metodosc(String hostname, int port, String[] filenames, String doctorUsername, String userUsername) {
        List<String> encryptedFiles = new ArrayList<>();
        try {
            for (String filename : filenames) {
                File file = new File(filename);
                if (!file.exists()) {
                    System.out.println("File " + filename + " does not exist. Skipping...");
                    continue; // Move to the next filename
                }

                // Check if the .cifrado file already exists on the server
                File cifradoFile = new File(filename + ".cifrado");
                if (cifradoFile.exists()) {
                    System.out.println("File " + cifradoFile.getName() + " already exists on the server. Skipping...");
                    continue; // Move to the next filename
                }

                // Check if the .chave_secreta.userUsername file already exists on the server
                File keyFile = new File(filename + ".chave_secreta." + userUsername);
                if (keyFile.exists()) {
                    System.out.println("File " + keyFile.getName() + " already exists on the server. Skipping...");
                    continue; // Move to the next filename
                }

                // Implement the logic to encrypt and send files to the server

                // Generate a random AES key
                KeyGenerator kg = KeyGenerator.getInstance("AES");
                kg.init(128);
                SecretKey aesKey = kg.generateKey();

                encryptFileWithAES(filename, aesKey);
                encryptAESKeyWithRSA(aesKey, userUsername, filename);
                // Store the encrypted filename for sending
                encryptedFiles.add(filename);
            }

            // After encrypting the files, send only the encrypted files to the server
            sendFilesToServer(encryptedFiles.toArray(new String[0]), userUsername);

        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error generating AES key: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }

    
    private static void metodosa(String hostname, int port, String[] filenames, String doctorUsername, String userUsername) throws IOException {
        // Itera sobre cada nome de arquivo fornecido
		for (String filename : filenames) {
		    // Verifica se o arquivo existe localmente
		    File file = new File(filename);
		    if (!file.exists()) {
		        System.out.println("O arquivo " + filename + " não existe localmente. Ignorando...");
		        continue; // Passa para o próximo nome de arquivo
		    }

		    // Verifica se o arquivo assinado correspondente já existe no servidor
		    File signedFile = new File(filename + ".assinado");
		    if (signedFile.exists()) {
		        System.out.println("O arquivo " + signedFile.getName() + " já existe no servidor. Ignorando...");
		        continue; // Passa para o próximo nome de arquivo
		    }

		    // Gera o nome do arquivo de assinatura
		    String signatureFileName = filename + ".assinatura." + doctorUsername;

		    // Assina o arquivo
		    signFile(file, signatureFileName);

		    // Envia o arquivo de assinatura para o servidor
		    sendFilesToServer(new String[]{signatureFileName}, userUsername);

		    // Envia o arquivo assinado para o servidor
		    sendFilesToServer(new String[]{filename}, userUsername);

		    System.out.println("O arquivo " + filename + " foi assinado e enviado para o servidor com sucesso.");
		}
    }

    
    
    private static void metodose(String hostname, int port, String[] filenames, String doctorUsername, String userUsername) throws IOException {
        // Itera sobre cada nome de arquivo fornecido
		for (String filename : filenames) {
		    // Verifica se o arquivo existe localmente
		    File file = new File(filename);
		    if (!file.exists()) {
		        System.out.println("O arquivo " + filename + " não existe localmente. Ignorando...");
		        continue; // Passa para o próximo nome de arquivo
		    }

		    // Verifica se o arquivo seguro correspondente já existe no servidor
		    File secureFile = new File(filename + ".seguro");
		    if (secureFile.exists()) {
		        System.out.println("O arquivo " + secureFile.getName() + " já existe no servidor. Ignorando...");
		        continue; // Passa para o próximo nome de arquivo
		    }

		    // Gera o nome do arquivo de envelope seguro
		    String secureFileName = filename + ".seguro";

		    // Cifra e assina o arquivo
		    encryptAndSignFile(file, secureFileName, userUsername, doctorUsername);

		    // Envia o arquivo seguro para o servidor
		    sendFilesToServer(new String[]{secureFileName}, userUsername);

		    // Envia as assinaturas - mesma lógica que o método metodosa
		    String signatureFileName = filename + ".assinatura." + doctorUsername;
		    signFile(file, signatureFileName);
		    sendFilesToServer(new String[]{signatureFileName}, userUsername);

		    // Envia as chaves - mesma lógica que o método metodosc
		    List<String> encryptedFiles = new ArrayList<>();
		    encryptedFiles.add(filename);
		    sendFilesToServer(encryptedFiles.toArray(new String[0]), userUsername);

		    System.out.println("O arquivo " + filename + " foi cifrado, assinado e enviado para o servidor com sucesso.");
		}
    }
    
    private static void signFile(File file, String signatureFileName) {
        // Implementa a lógica para assinar o arquivo com a assinatura do médico para o -SA
    	//PEGAR O DA TP
    }
    
    
    private static void encryptAndSignFile(File file, String secureFileName, String userUsername, String doctorUsername) {
    	//Implementar lógica para cifrar e assinar ficheiro para o -SE
    }

    
    
   
    private static void encryptAESKeyWithRSA(SecretKey aesKey, String userUsername, String filename) throws FileNotFoundException, IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException {
        try (FileOutputStream kos = new FileOutputStream(filename + ".chave_secreta." + userUsername)) {
            FileInputStream kfile = new FileInputStream("keystore." + userUsername);
            KeyStore kstore = KeyStore.getInstance("PKCS12");
            kstore.load(kfile, "123456".toCharArray()); // password
            Certificate cert = kstore.getCertificate(userUsername);
            // alias do utilizador
            Cipher c1 = Cipher.getInstance("RSA");
            c1.init(Cipher.WRAP_MODE, cert);
            byte[] keyEncoded = c1.wrap(aesKey);

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

    private static void sendFilesToServer(String[] filenames, String userUsername) {
        try {
            ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());
            
            // Send initial data
            outStream.writeObject(userUsername);
            
            outStream.writeObject(false);
           
            
         // Send each encrypted file to the server
            for (String filename : filenames) {
                // Send .cifrado file
                File cifradoFile = new File(filename + ".cifrado");
                Long fileSize = cifradoFile.length();
                outStream.writeObject(fileSize); // Send file size to the server
                outStream.writeObject(filename + ".cifrado"); // Send file name to the server
                
             

                
                try (BufferedInputStream cifradoFileB = new BufferedInputStream(new FileInputStream(cifradoFile))) {
                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = cifradoFileB.read(buffer, 0, 1024)) > 0) {
                        outStream.write(buffer, 0, bytesRead);
                    }
                }

                // Send .key file
                File keyFile = new File(filename + ".chave_secreta." + userUsername);
                fileSize = keyFile.length();
                outStream.writeObject(fileSize); // Send file size to the server
                outStream.writeObject(filename + ".chave_secreta." + userUsername); // Send file name to the server
                try (BufferedInputStream keyFileB = new BufferedInputStream(new FileInputStream(keyFile))) {
                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = keyFileB.read(buffer, 0, 1024)) > 0) {
                        outStream.write(buffer, 0, bytesRead);
                    }
                }
            }
            // Send end-of-file indicator to the server
            outStream.writeObject(-1L); // Indicate end of file transfer
            outStream.flush(); // Flush the stream to ensure all data is sent

            // Wait for acknowledgment from the server
            Boolean acknowledgment = (Boolean) inStream.readObject();
            System.out.println("Server acknowledgment: " + acknowledgment);

            // Close the input and output streams
            inStream.close();
            outStream.close();

            // Close the socket after receiving acknowledgment
            socket.close();
            System.out.println("Connection closed.");

        } catch (IOException | ClassNotFoundException e) {
            System.err.println("Error sending files to the server: " + e.getMessage());
        }
    }
    
    //responsável por solicitar arquivos específicos do servidor e recebê-los
    private static void getFilesFromServer(String[] filenames, String userUsername) throws ClassNotFoundException {
        try (ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream())) {

            // Send the command to the server
        	outStream.writeObject(userUsername);   
        	outStream.writeObject(true);

            for (String filename : filenames) {
                // Send the filename to the server
                outStream.writeObject(filename);
                System.out.println("send file name");
             // Receive the name file from the server
                String name = (String) inStream.readObject();
                System.out.println("receive filename");

                // Receive the file size from the server
                long fileSize = (long) inStream.readObject();
                System.out.println("receive filesize");
                if (fileSize == -1) {
                    System.out.println("File " + filename + " not found on the server.");
                    continue;
                }
                System.out.println("EEEEEEEEEEEEEE");
                // Receive the encrypted file
                if (fileSize > 0) {
                    try (FileOutputStream fileOutputStream = new FileOutputStream(name)) {
                        byte[] buffer = new byte[1024];
                        int bytesRead;
                        long remainingBytes = fileSize;
                        while (remainingBytes > 0 && (bytesRead = inStream.read(buffer, 0, (int) Math.min(buffer.length, remainingBytes))) != -1) {
                            fileOutputStream.write(buffer, 0, bytesRead);
                            remainingBytes -= bytesRead;
                        }
                        System.out.println("Encrypted file " + name + " retrieved from the server.");
                    }
                } else {
                    System.out.println("File size is 0 for file: " + name);
                }
            }
        } catch (IOException e) {
            System.err.println("Error retrieving files from the server: " + e.getMessage());
        }
    }
}
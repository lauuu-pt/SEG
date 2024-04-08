package client;
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
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class mySNS {

    private static Socket socket;

    
    /**
     * Método principal para iniciar o cliente mySNS.
     * @param args Argumentos da linha de comando.
     */
    public static void main(String[] args){
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
            
            socket = new Socket(hostname, port);
            System.out.println("Connected to the server.");
            String userUsername = args[3];
           
            if (args.length >= 6 && args[4].equals("-g")) {
                System.out.println("Vale");
                if (args.length > 6) {
                
                    String[] filenames = new String[args.length - 5];
                    for(int i=5;i<filenames.length;i++) {
                    	System.arraycopy(args, 5, filenames, 0, filenames.length);
                    }
                    for (String filename : filenames) {
                        System.out.println("Filename: " + filename);
                        try {
                        	System.out.println(filenames);
							getFilesFromServer(new String[] { filename }, userUsername);
						} catch (ClassNotFoundException e) {
							e.printStackTrace();
						}
                    }
                } else if (args.length == 6) {
                    String filename = args[5];
                    System.out.println("Filename1: " + filename);
                    getFilesFromServer(new String[] {filename}, userUsername);
                } else {
                    System.out.println("No filenames provided.");
                }
            }

            
             else if (args.length >= 8) {
            	 String doctorUsername = args[3];
                 String userUsernamee = args[5];

                
                 File medicoFile = new File("keystore." + doctorUsername);
                 if (!medicoFile.exists()) {
                     System.out.println("Keystore do medico " + doctorUsername + " nao existe");
                     return;
                 }

               
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
                        deleteFiles(filenames, userUsernamee, doctorUsername);
                        break;
                    case "-sa":
                        metodosa(hostname, port, filenames, doctorUsername, userUsernamee);
                        deleteFiles(filenames, userUsernamee, doctorUsername);
                        break;
                    case "-se":
                        metodose(hostname, port, filenames, doctorUsername, userUsernamee);
                        deleteFiles(filenames, userUsernamee, doctorUsername);
                        break;
                    default:
                        System.out.println("Invalid command: " + command);
                }
            } else {
                System.out.println("Invalid command or combination of commands.");
            }


        } catch (UnknownHostException e) {
            System.err.println("Error connecting to the server. Unknown server address: " + hostname);
        } catch (IOException e) {
            System.err.println("Error connecting to the server: " + e.getMessage());
        } catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
    }

    
    /**
     * Método para deletar arquivos cifrados e chaves secretas associadas.
     * 
     * @param filenames   Nomes dos arquivos a serem deletados.
     * @param userUsername  Nome de usuário do usuário.
     */
    private static void deleteFiles(String[] filenames,String userUsername,String doctorUsername) {
   	 for (String filename : filenames) {
   	        File cifradoFile = new File(filename + ".cifrado");
   	        File keyFile = new File(filename + ".chave_secreta." + userUsername);
   	        File signedFile = new File(filename + ".assinado");
   	        File signature = new File(filename + ".assinatura." + doctorUsername);
   	        File cifradoAss = new File(filename + ".cifrado.assinado");
   	        File CifAss = new File(filename + ".cifrado.assinatura." + doctorUsername);

   	        if (cifradoFile.exists()) {
   	            cifradoFile.delete();
   	        }
   	        if (keyFile.exists()) {
   	            keyFile.delete();
   	        }
   	        if (signedFile.exists()) {
   	            signedFile.delete();
   	        }
   	        if (signature.exists()) {
   	            signature.delete(); 
   	        }
   	        if (cifradoAss.exists()) {
   	        	cifradoAss.delete(); 
   	        }
   	        if (CifAss.exists()) {
   	        	CifAss.delete(); 
   	        }
   	    }
	}

    
    /**
     * Método para executar o comando "-sc" (cifra o ficheiro) no cliente mySNS.
     * 
     * @param hostname       Nome do host do servidor.
     * @param port           Número da porta do servidor.
     * @param filenames      Nomes dos arquivos a serem cifrados.
     * @param doctorUsername Nome de usuário do médico.
     * @param userUsername   Nome de usuário do usuário.
     */
    private static void metodosc(String hostname, int port, String[] filenames, String doctorUsername, String userUsername) {
        List<String> encryptedFiles = new ArrayList<>();
        try {
        	
            for (String filename : filenames) {
                File file = new File(filename);
                if (!file.exists()) {
                    System.out.println("File " + filename + " does not exist. Skipping...");
                    continue; 
                }

                /*
                File cifradoFile = new File(filename + ".cifrado");
                if (cifradoFile.exists()) {
                    System.out.println("File " + cifradoFile.getName() + " already exists on the server. Skipping...");
                    continue; 
                }
                
                
                File keyFile = new File(filename + ".chave_secreta." + userUsername);
                if (keyFile.exists()) {
                    System.out.println("File " + keyFile.getName() + " already exists on the server. Skipping...");
                    continue; 
                }*/

                
                KeyGenerator kg = KeyGenerator.getInstance("AES");
                kg.init(128);
                SecretKey aesKey = kg.generateKey();

                encryptFileWithAES(filename, aesKey);
                encryptAESKeyWithRSA(aesKey, userUsername, filename);
            
                encryptedFiles.add(filename);
                
            }
            sendFilesToServer(encryptedFiles.toArray(new String[0]), userUsername);
            socket.close();
            

        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error generating AES key: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }

    
    /**
     * Método para executar o comando "-sa" (Assina ficheiro)
     * 
     * @param hostname       Nome do host do servidor.
     * @param port           Número da porta do servidor.
     * @param filenames      Nomes dos arquivos a serem Assinados.
     * @param doctorUsername Nome de usuário do médico.
     * @param userUsername   Nome de usuário do usuário.
     */
    private static void metodosa(String hostname, int port, String[] filenames, String doctorUsername, String userUsername) {
    	List<String> signedFiles = new ArrayList<>();
    	try {
			for (String filename : filenames) { // para cada ficheiro dado no comando
			    
			    File file = new File(filename);
			    if (!file.exists()) {
			        System.out.println("O arquivo " + filename + " não existe localmente. Ignorando...");
			        continue; 
			    }
			    
			    signFile(filename, doctorUsername);
	
			   
			    signedFiles.add(filename);
	
			    System.out.println("O arquivo " + filename + " foi assinado ");
			    
			}
			sendFilesToServer2(signedFiles.toArray(new String[0]), userUsername, doctorUsername); 
			
			socket.close();
    	} catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    	
    }
	
    
    /**
     * Método para executar o comando "-se" (Cifra e Assina os ficheiros)
     * 
     * @param hostname       Nome do host do servidor.
     * @param port           Número da porta do servidor.
     * @param filenames      Nomes dos arquivos a serem Cifrados e Assinados.
     * @param doctorUsername Nome de usuário do médico.
     * @param userUsername   Nome de usuário do usuário.
     */
    private static void metodose(String hostname, int port, String[] filenames, String doctorUsername, String userUsername) {

        List<String> seFiles = new ArrayList<>();

        for (String filename : filenames) {

            File file = new File(filename);
            if (!file.exists()) {
                System.out.println("O ficheiro " + filename + " não existe localmente. Ignorando...");
                continue; 
            }


            File secureFile = new File(filename + ".seguro");
            if (secureFile.exists()) {
                System.out.println("O ficheiro " + secureFile.getName() + " já existe no servidor. Ignorando...");
                continue; 
            }

            envelopesSeguros(userUsername, filename, doctorUsername);


            seFiles.add(filename);
            
            System.out.println("O ficheiro " + filename + " foi cifrado, assinado e enviado para o servidor com sucesso. ->" + filename+".seguro");
        }
        sendFilesToServer3(seFiles.toArray(new String[0]), userUsername, doctorUsername);
        try {
			socket.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }

    
    
     private static void sendFilesToServer3(String[] filenames, String userUsername, String doctorUsername) {
    	 try {
             ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());
             
             
             outStream.writeObject(userUsername);            
             outStream.writeObject(false);
                   
             for (String filename : filenames) {
              

                 // Send .key file
                 File keyFile = new File(filename + ".chave_secreta." + userUsername);
                 Long fileSize = keyFile.length();
                 outStream.writeObject(fileSize); 
                 outStream.writeObject(filename + ".chave_secreta." + userUsername); 
                 try (BufferedInputStream keyFileB = new BufferedInputStream(new FileInputStream(keyFile))) {
                     byte[] buffer = new byte[1024];
                     int bytesRead;
                     while ((bytesRead = keyFileB.read(buffer, 0, 1024)) > 0) {
                         outStream.write(buffer, 0, bytesRead);
                     }
                 }
                 File assinaturaFile = new File(filename+".cifrado.assinatura."+doctorUsername);
                 fileSize = assinaturaFile.length();
                 outStream.writeObject(fileSize); 
                 outStream.writeObject(filename+".assinatura."+doctorUsername); 
                 try (BufferedInputStream assinaturaFileB = new BufferedInputStream(new FileInputStream(assinaturaFile))) {
                     byte[] buffer = new byte[1024];
                     int bytesRead;
                     while ((bytesRead = assinaturaFileB.read(buffer, 0, 1024)) > 0) {
                         outStream.write(buffer, 0, bytesRead);
                     }
                 }
                 File seguroFile = new File(filename+".cifrado.assinado");
                 fileSize = seguroFile.length();
                 outStream.writeObject(fileSize); 
                 outStream.writeObject(filename+".seguro"); 
                 try (BufferedInputStream seguroFileB = new BufferedInputStream(new FileInputStream(seguroFile))) {
                     byte[] buffer = new byte[1024];
                     int bytesRead;
                     while ((bytesRead = seguroFileB.read(buffer, 0, 1024)) > 0) {
                         outStream.write(buffer, 0, bytesRead);
                     }
                 }

                 
             }
             outStream.writeObject(-1L); 
             outStream.flush(); // Flush the stream to ensure all data is sent

             
             Boolean acknowledgment = (Boolean) inStream.readObject();
             System.out.println("Server acknowledgment: " + acknowledgment);

             
             inStream.close();
             outStream.close();

             
             socket.close();
             System.out.println("Connection closed.");

             } catch (IOException | ClassNotFoundException e) {
             System.err.println("Error sending files to the server: " + e.getMessage());
         }
     }
	


     /**
      * Método chamado em metodog para criar envelopes de segurança para um arquivo.
      * 
      * @param userUsername    O nome de usuário do destinatário.
      * @param filename        O nome do arquivo a ser envolvido.
      * @param doctorUsername  O nome de usuário do médico responsável pela assinatura.
      */
     private static void envelopesSeguros(String userUsername, String filename, String doctorUsername) {
    	 KeyGenerator kg;
	     try {
	         kg = KeyGenerator.getInstance("AES");
	         kg.init(128);
	         SecretKey aesKey = kg.generateKey();
	         try {
	             encryptFileWithAES(filename, aesKey);
	             try {
				encryptAESKeyWithRSA(aesKey, userUsername, filename);
			} catch (NoSuchPaddingException e) {
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
				}
	        } catch (IOException e) {
	             e.printStackTrace();}
	         signFile(filename + ".cifrado", doctorUsername);
		
	     } catch (NoSuchAlgorithmException | UnrecoverableKeyException | InvalidKeyException | KeyStoreException | CertificateException | SignatureException | IOException e) {
	          e.printStackTrace();}}

    
     
     /**
      * Método para assinar um arquivo com a chave privada do médico.
      * 
      * @param file           Nome do arquivo a ser assinado.
      * @param doctorUsername Nome de usuário do médico.
      */
    private static void signFile(String file, String doctorUsername) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException, SignatureException, InvalidKeyException {

    	FileInputStream fis = new FileInputStream(file);
    	FileOutputStream fos = new FileOutputStream(file+".assinado");
    	FileOutputStream fos2 = new FileOutputStream(file+".assinatura."+doctorUsername);
    	// Ler a chave privada do médico
    	FileInputStream kfile1 = new FileInputStream("keystore." + doctorUsername); //ler a keystore
    	KeyStore kstore = KeyStore.getInstance("PKCS12");
    	kstore.load(kfile1, "123456".toCharArray());
    	PrivateKey myPrivateKey = (PrivateKey) kstore.getKey(doctorUsername, "123456".toCharArray());

    	// Criar o objeto para criar a assinatura com a chave privada
    	Signature s = Signature.getInstance("MD5withRSA");
    	s.initSign(myPrivateKey);


    	byte[] b = new byte[1024];  // leitura
    	int i = fis.read(b);
    	while (i != -1) { // quando for igual a -1 cheguei ao fim do ficheiro
    		s.update(b, 0, i);
    		fos.write(b,0,i);
    		i = fis.read(b); // leitura
    	}
    	byte[] signature2 = s.sign();

    	fos.write(s.sign());
    	fos2.write(signature2);
    	fos.close();
    	fis.close();



    }
    
   
    /**
     * Método para cifrar uma chave AES com uma chave pública RSA e salvar no disco.
     * 
     * @param aesKey       A chave AES a ser cifrada.
     * @param userUsername Nome de usuário do usuário.
     * @param filename     Nome do arquivo onde a chave cifrada será salva.
     */
    private static void encryptAESKeyWithRSA(SecretKey aesKey, String userUsername, String filename) throws FileNotFoundException, IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException {
        try (FileOutputStream kos = new FileOutputStream(filename + ".chave_secreta." + userUsername)) {
            FileInputStream kfile = new FileInputStream("keystore." + userUsername);
            KeyStore kstore = KeyStore.getInstance("PKCS12");
            kstore.load(kfile, "123456".toCharArray()); 
            Certificate cert = kstore.getCertificate(userUsername);
            
            Cipher c1 = Cipher.getInstance("RSA");
            c1.init(Cipher.WRAP_MODE, cert);
            byte[] keyEncoded = c1.wrap(aesKey);

            kos.write(keyEncoded);
            kos.close();

        }
    }

    
    /**
     * Método para cifrar um arquivo usando AES e salvar no disco.
     * 
     * @param filename Nome do arquivo a ser cifrado.
     * @param aesKey   A chave AES usada para cifrar o arquivo.
     */
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

    
    /**
     * Método para obter uma instância do Cipher AES.
     * 
     * @param aesKey A chave AES usada para inicializar o Cipher.
     * @return O objeto Cipher configurado para criptografar com AES.
     */
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
            
            
            outStream.writeObject(userUsername);
            
            outStream.writeObject(false);
     
            for (String filename : filenames) {
             
                File cifradoFile = new File(filename + ".cifrado");
                Long fileSize = cifradoFile.length();
                outStream.writeObject(fileSize); 
                outStream.writeObject(filename + ".cifrado"); 
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
                outStream.writeObject(fileSize); 
                outStream.writeObject(filename + ".chave_secreta." + userUsername); 
                try (BufferedInputStream keyFileB = new BufferedInputStream(new FileInputStream(keyFile))) {
                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = keyFileB.read(buffer, 0, 1024)) > 0) {
                        outStream.write(buffer, 0, bytesRead);
                    }
                }

                
            }
            outStream.writeObject(-1L); 
            outStream.flush(); // Flush the stream to ensure all data is sent

            
            Boolean acknowledgment = (Boolean) inStream.readObject();
            System.out.println("Server acknowledgment: " + acknowledgment);

            
            inStream.close();
            outStream.close();

            
            socket.close();
            System.out.println("Connection closed.");

            } catch (IOException | ClassNotFoundException e) {
            System.err.println("Error sending files to the server: " + e.getMessage());
        }
    }
    private static void sendFilesToServer2(String[] filenames, String userUsername,String doctorUsername) {
        try {
            ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());
            
            
            outStream.writeObject(userUsername);
            
            outStream.writeObject(false);
           
            
            
            
     
            for (String filename : filenames) {
             
            	File assinadoFile = new File(filename+".assinado");
                Long fileSize = assinadoFile.length();
                outStream.writeObject(fileSize); 
                outStream.writeObject(filename + ".assinado"); 
                try (BufferedInputStream assinadoFileB = new BufferedInputStream(new FileInputStream(assinadoFile))) {
                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = assinadoFileB.read(buffer, 0, 1024)) > 0) {
                        outStream.write(buffer, 0, bytesRead);
                    }
                }
                File assinaturaFile = new File(filename+".assinatura."+doctorUsername);
                fileSize = assinaturaFile.length();
                outStream.writeObject(fileSize); 
                outStream.writeObject(filename+".assinatura."+doctorUsername); 
                try (BufferedInputStream assinaturaFileB = new BufferedInputStream(new FileInputStream(assinaturaFile))) {
                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = assinaturaFileB.read(buffer, 0, 1024)) > 0) {
                        outStream.write(buffer, 0, bytesRead);
                    }
                }

                
            }
            outStream.writeObject(-1L); 
            outStream.flush(); // Flush the stream to ensure all data is sent

            
            Boolean acknowledgment = (Boolean) inStream.readObject();
            System.out.println("Server acknowledgment: " + acknowledgment);

            
            inStream.close();
            outStream.close();

            
            socket.close();
            System.out.println("Connection closed.");

            } catch (IOException | ClassNotFoundException e) {
            System.err.println("Error sending files to the server: " + e.getMessage());
        }
    }
    
    
    /**
     * Método para receber arquivos do servidor.
     * 
     * @param filenames     Nomes dos arquivos a serem recebidos.
     * @param userUsername  Nome de usuário do usuário.
     */
    private static void getFilesFromServer(String[] filenames, String userUsername) throws ClassNotFoundException {
    	
        List<String> filesList = new ArrayList<>();
    	
        try (ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream())) {

            
        	outStream.writeObject(userUsername);   
        	outStream.writeObject(true);
        	
            for (String filename : filenames) {
                
                outStream.writeObject(filename);
                System.out.println("send file name");
             
                String name = (String) inStream.readObject();
                System.out.println("receive filename");

                
                long fileSize = (long) inStream.readObject();
                System.out.println("receive filesize");
                if (fileSize == -1) {
                    System.out.println("File " + filename + " not found on the server.");
                    continue;
                }
                
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
                        filesList.add(name);
                    }
                    //metodog(filesList.toArray(new String[0]));
                    System.out.println("testando");
                } else {
                    System.out.println("File size is 0 for file: " + name);
                }
            }
        } catch (IOException e) {
            System.err.println("Error retrieving files from the server: " + e.getMessage());
        }
    }
    
    
    /**
	 * Método para realizar operações(descifrar e verificar assinatura) em uma lista de arquivos.
	 * 
	 * @param filenames Os nomes dos arquivos nos quais as operações serão realizadas.
	 */
    private static void metodog(String[] filenames) {
	       
    	Pattern padraoC = Pattern.compile("\\.cifrado$");
    	Pattern padraoA = Pattern.compile("\\.assinado$");
    	
    	for (String filename : filenames) { // para cada ficheiro dado no comando
		    
		    File file = new File(filename);
		    if (!file.exists()) {
		        System.out.println("O ficheiro " + filename + " não existe localmente. Ignorando...");
		        continue; 
		    }
		    
		    Matcher matcherC = padraoC.matcher(filename);
		    Matcher matcherA = padraoA.matcher(filename);
		    
		    if (matcherC.find()) {
		    	
		    	String[] args = filename.split("\\.");
		    	String userUsername = args[3];
		    	
		    	for (String filenameAES : filenames) {
		    		
		    		String[] argsAES = filenameAES.split("\\.");
		    		String AES = argsAES[0] + args[1];
		    		String extensão = argsAES[2];
		    		
		    		if(filename.equals(AES) && !extensão.equals(".cifrado")){		    			
		    			decifraFile(filename, filenameAES, userUsername);
		    			break;
	    			}
		    	}    	
		    	
		    	
		    } else if (matcherA.find()) {
		    	
		    	String[] args = filename.split("\\.");
		    	String assinatura = args[2];
		    	
		    	for (String filenameAss : filenames) {
		    
		    		String[] argsAss = filenameAss.split("\\.");
		    		String nome = argsAss[0] + argsAss[1];
		    		String extensão = argsAss[2];
		    		
		    		if(filename.equals(nome) && !extensão.equals(".assinado")){
		    			String user = argsAss[3];
		    			verificaAssinatura(filenameAss, assinatura, user);
		    			break;
		    		}
		    	}	
		    } 
    	}
    }
    
    
    
    /**
     * Método para descriptografar um arquivo usando uma chave AES.
     * 
     * @param filename    Nome do arquivo cifrado.
     * @param key         Nome do arquivo contendo a chave secreta.
     * @param userUsername  Nome de usuário do usuário.
     */
    private static void decifraFile(String filename, String key, String userUsername) {
        try {
            byte[] keyEncoded = new byte[256];
            FileInputStream kfile = new FileInputStream(key);
            kfile.read(keyEncoded);
            kfile.close();

            // Obter a chave privada da keystore
            FileInputStream kfile1 = new FileInputStream("keystore." + userUsername); // ver keystore do user
            KeyStore kstore = KeyStore.getInstance("PKCS12");
            kstore.load(kfile1, "123456".toCharArray());

            Key myPrivateKey = kstore.getKey(userUsername, "123456".toCharArray());

            // Decifrar chave AES com a chave RSA
            Cipher c1 = Cipher.getInstance("RSA");
            c1.init(Cipher.UNWRAP_MODE, myPrivateKey);
            Key aesKey = c1.unwrap(keyEncoded, "AES", Cipher.SECRET_KEY);

            // Decifrar
            Cipher c2 = Cipher.getInstance("AES");
            c2.init(Cipher.DECRYPT_MODE, aesKey);

            FileInputStream fis = new FileInputStream(filename);

            String[] nome = filename.split("\\.");
            String nomeCOS = nome[0] + nome[1];

            FileOutputStream fos = new FileOutputStream(nomeCOS);
            CipherInputStream cis = new CipherInputStream(fis, c2);

            byte[] buffer = new byte[1024];

            int i = cis.read(buffer);
            while (i != -1) { // Quando for igual a -1 chegou ao fim do ficheiro
                fos.write(buffer, 0, i); // Escrita do ficheiro lido com o tamanho do que lemos
                i = fis.read(buffer); // Leitura
            }

            fos.close();
            cis.close();
            fis.close();
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException | NoSuchPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }	    
    
    
    /**
     * Método para verificar a assinatura digital de um arquivo.
     * 
     * @param fileName   Nome do arquivo a ser verificado.
     * @param assinatura Assinatura digital do arquivo.
     * @param user       Nome de usuário do usuário.
     */
    private static void verificaAssinatura(String fileName, String assinatura, String user) {
    	
        // Ler a assinatura
        byte[] assinaturaOriginal = new byte[256];
        try {
            FileInputStream kfile = new FileInputStream(fileName);
            kfile.read(assinaturaOriginal);
            kfile.close();
        } catch (IOException e) {
            e.printStackTrace();
            return; 
        }
        
        try {
            // Ler a chave privada
            FileInputStream kfile1 = new FileInputStream("keystore" + user);
            KeyStore kstore = KeyStore.getInstance("PKCS12");
            kstore.load(kfile1, "123456".toCharArray()); // Lê a keystore com a password dada
            Certificate cert = kstore.getCertificate(user);
            
            // Criar o objeto para criar a assinatura com a chave privada
            Signature s = Signature.getInstance("SHA256withRSA");
            s.initVerify(cert);
                    
            FileInputStream fis; // Usado para ler o conteudo
            fis = new FileInputStream(fileName);
            
            byte[] b = new byte[1024];  // Leitura
            int i = fis.read(b);
            while (i != -1) { // Quando for igual a -1 chegou-se ao fim do ficheiro
                s.update(b, 0, i);
                i = fis.read(b); // Leitura
            }
            
            s.verify(assinaturaOriginal);
            fis.close();
            
        } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException | SignatureException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }    
}
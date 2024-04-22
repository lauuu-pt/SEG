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
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class mySNS {
	/*Membros do grupo:
	Laura Tomás (58641)
	Maria Beatriz Guerreiro (58643)
	Maria Rita Gonçalves (58659)*/
	
    private static Socket socket;

    
    /**
     * Método principal para iniciar o cliente mySNS.
     * @param args Argumentos da linha de comando.
     * @throws SignatureException 
     * @throws CertificateException 
     * @throws NoSuchAlgorithmException 
     * @throws KeyStoreException 
     * @throws InvalidKeyException 
     */
    public static void main(String[] args) throws InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, SignatureException{
        if (args.length < 6 || !args[0].equals("-a") ) {
            System.out.println("Uso: java mySNS -a <serverAddress> -m <doctorUsername> -u <userUsername> [-sc <filenames>] [-sa <filenames>] [-se <filenames>] [-g <filenames>]\nou\nUsage: java mySNS -a <serverAddress> -u <username do utente> -g {<filenames>}+");
            return;
        }

        String serverAddress = args[1];
        String[] addressParts = serverAddress.split(":");
        if (addressParts.length != 2) {
            System.out.println("endereco invalido. Usar: hostname:port");
            return;
        }

        String hostname = addressParts[0];
        int port;
        try {
            port = Integer.parseInt(addressParts[1]);
        } catch (NumberFormatException e) {
            System.out.println("Porto tem de ser um inteiro");
            return;
        }

        

        try {
            
            socket = new Socket(hostname, port);
            System.out.println("Conectado ao servidor.");
            String userUsername = args[3];
            List<String> ficheirosRecebidos = new ArrayList<>();
            String doctor;
            
            if (args.length >= 6 && args[4].equals("-g")) {
            	ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
            	ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());
            	outStream.writeObject(userUsername);
            	outStream.writeObject(true);
            	// Determine the count of files to be sent
                int fileCount = 0;

                // Increment file count for each valid file
                for (int i = 5; i < args.length; i++) {
                    File file = new File(args[i]);
                    
                    fileCount++;
                                 
                    
                }
                System.out.println("n ficheiros a pedir: "+fileCount);
                // Send the count of files to the server
               
                outStream.writeInt(fileCount);
                outStream.flush();
                for (int i = 5; i < args.length; i++) {
                    File file = new File(args[i]);
                    
                        // Send the filename to the server
                        outStream.writeObject(file.getName());
                        outStream.flush();
                    
                }                              
               
                    int existingFileCount = (int) inStream.readObject();
                    System.out.println("Server has " + existingFileCount + " existing files.");
                
                
                for(int j =0; j<existingFileCount; j++) {
                	String filename = (String) inStream.readObject();
                	long fileSize = (long) inStream.readObject();
                	try (FileOutputStream fos = new FileOutputStream(filename)){
                		byte[] buffer = new byte[1024];
                        int bytesRead;
                        long total=0;
                        while (total<fileSize && (bytesRead=inStream.read(buffer)) != -1) {
                       	 	fos.write(buffer,0,bytesRead);
                       	 	total+=bytesRead;
                        }
                        System.out.println("ficheiro "+filename+" recebido");
                        ficheirosRecebidos.add(filename);
                        
                    }                	
                }                
                
                for(String ficheiro : ficheirosRecebidos){
                	
                	String[] lista = ficheiro.split("\\.");
                	String extensao = lista[lista.length-1];
                	
                	if(extensao.equals("cifrado")) {
                		String chave = lista[0]+"."+lista[1]+".chave_secreta."+ userUsername;
                		System.out.println("------------------------------------------------------------------");
                		decifraFile(ficheiro,chave,userUsername);
                		System.out.println("------------------------------------------------------------------");
                		
                	}else if(extensao.equals("assinado")) {
                		
                		for(String teste : ficheirosRecebidos) {
                			if(teste.startsWith(lista[0]+"."+lista[1]+".assinatura.")) {
                            	String[] fic = teste.split("\\.");
                            	doctor = fic[3];
                        		System.out.println("------------------------------------------------------------------");
                            	verificaAssinatura(ficheiro, doctor);
                        		System.out.println("------------------------------------------------------------------");
                            }
                		}

                	}else if (extensao.equals("seguro")) {
                		System.out.println("------------------------------------------------------------------");
                		String chave = lista[0]+"."+lista[1]+".chave_secreta."+ userUsername;
                		
                		for(String teste : ficheirosRecebidos) {
                			if(teste.startsWith(lista[0]+"."+lista[1]+".assinatura.")) {
                            	String[] fic = teste.split("\\.");
                            	doctor = fic[3];
                            	decifraFile(ficheiro,chave,userUsername);
                           
                            	verificaAssinatura(lista[0]+"."+lista[1], doctor);
                            	
                        		System.out.println("------------------------------------------------------------------");
                        		
                        		

                            }
                		}
                	}
                
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
                        System.out.println("Comando invalido: " + command);
                }
            } else {
                System.out.println("Comando invalido ou combinacao invalida");
            }


        } catch (UnknownHostException e) {
            System.err.println("Erro ao ligar ao servidor. Edereco desconhecido: " + hostname);
        } catch (IOException e) {
            System.err.println("Erro ao ligar ao servidor: " + e.getMessage());
        } catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
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
                    System.out.println("O arquivo " + filename + " não existe localmente. Ignorando...");
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
            System.err.println("Erro ao gerar chave AES: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Erro: " + e.getMessage());
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
			for (String filename : filenames) { 
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
            System.err.println("Erro: " + e.getMessage());
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


            /*File secureFile = new File(filename + ".seguro");
            if (secureFile.exists()) {
                System.out.println("O ficheiro " + secureFile.getName() + " já existe no servidor. Ignorando...");
                continue; 
            }*/

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
                 File seguroFile = new File(filename+".assinado.cifrado");
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
             outStream.flush(); 

             
             Boolean acknowledgment = (Boolean) inStream.readObject();
             //System.out.println("Server acknowledgment: " + acknowledgment);

             
             inStream.close();
             outStream.close();

             
             socket.close();
             System.out.println("Conexao fechada.");

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
	        	 signFile(filename, doctorUsername);
	             encryptFileWithAES(filename+".assinado", aesKey);
	             try {
				encryptAESKeyWithRSA(aesKey, userUsername, filename);
			} catch (NoSuchPaddingException e) {
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
				}
	        } catch (IOException e) {
	             e.printStackTrace();}
	         
		
	     } catch (NoSuchAlgorithmException | UnrecoverableKeyException | InvalidKeyException | KeyStoreException | CertificateException | SignatureException e) {
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
    	FileInputStream kfile1 = new FileInputStream("keystore." + doctorUsername); //ler a keystore
    	
    	KeyStore kstore = KeyStore.getInstance("PKCS12");
    	kstore.load(kfile1, "123456".toCharArray());
    	Key myPrivateKey = kstore.getKey(doctorUsername, "123456".toCharArray());

    	PrivateKey pk = (PrivateKey) myPrivateKey;
    	
    	Signature s = Signature.getInstance("MD5withRSA");
    	s.initSign(pk);


    	byte[] b = new byte[1024];  
    	int i = fis.read(b);
    	
    	while (i != -1) { 
    		s.update(b, 0, i);
    		fos.write(b,0,i);
    		i = fis.read(b); 
    	}
    	byte[] signature = s.sign();
    	fos.write(signature);
    	fos2.write(signature);
    	
    	fos.close();
    	fis.close();
    	fos2.close();

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
        System.out.println("Ficheiro cifrado: " + filename + " -> " + filename + ".cifrado");
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
            outStream.flush(); 

            
            Boolean acknowledgment = (Boolean) inStream.readObject();
            //System.out.println("Server acknowledgment: " + acknowledgment);

            
            inStream.close();
            outStream.close();

            
            socket.close();
            System.out.println("Conexao fechada.");

            } catch (IOException | ClassNotFoundException e) {
            System.err.println("Erro ao enviar ficheiros para o servidor: " + e.getMessage());
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
            outStream.flush(); 

            
            Boolean acknowledgment = (Boolean) inStream.readObject();
            //System.out.println("Server acknowledgment: " + acknowledgment);

            
            inStream.close();
            outStream.close();

            
            socket.close();
            System.out.println("Conexao fechada.");

            } catch (IOException | ClassNotFoundException e) {
            System.err.println("Erro ao enviar ficheiros para o servidor: " + e.getMessage());
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

            
            FileInputStream kfile1 = new FileInputStream("keystore." + userUsername); 
            KeyStore kstore = KeyStore.getInstance("PKCS12");
            kstore.load(kfile1, "123456".toCharArray());

            Key myPrivateKey = kstore.getKey(userUsername, "123456".toCharArray());

            
            Cipher c1 = Cipher.getInstance("RSA");
            c1.init(Cipher.UNWRAP_MODE, myPrivateKey);
            Key aesKey = c1.unwrap(keyEncoded, "AES", Cipher.SECRET_KEY);

            
            Cipher c2 = Cipher.getInstance("AES");
            c2.init(Cipher.DECRYPT_MODE, aesKey);

            FileInputStream fis = new FileInputStream(filename);

            String[] nome = filename.split("\\.");
            String nomeCOS = nome[0] +"."+ nome[1];

            FileOutputStream fos = new FileOutputStream(nomeCOS);
            CipherInputStream cis = new CipherInputStream(fis, c2);

            byte[] buffer = new byte[1024];
            int i = cis.read(buffer);
            while (i != -1) { 
                fos.write(buffer, 0, i); 
                i = cis.read(buffer); 
            }
    		System.out.println("ficheiro"+ filename + " decifrado");


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
     * @param doctor     Nome do doctor.
     * @throws KeyStoreException 
     * @throws IOException 
     * @throws CertificateException 
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeyException 
     * @throws SignatureException 
     */
    private static void verificaAssinatura(String filename, String doctor) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, InvalidKeyException, SignatureException {
   
		FileInputStream fis = new FileInputStream(filename);
		
		long datalen = new File(filename).length() - 256;
		
		FileInputStream kis = new FileInputStream("keystore." + doctor);
		KeyStore kstore = KeyStore.getInstance("PKCS12");
		kstore.load(kis,"123456".toCharArray());
		
		Certificate c = kstore.getCertificate(doctor);
		PublicKey pubk = c.getPublicKey();
		
		Signature s = Signature.getInstance("MD5withRSA");
		s.initVerify(pubk);
		
		byte [] b = new byte[16];
		int i;
		
		while(datalen>0) {
			i=fis.read(b,0,(int)datalen>16 ? 16 : (int) datalen);
			s.update(b,0,i);
			datalen -= i;
		}
		byte [] signature  = new byte [256];
		fis.read(signature);
		
		if (s.verify(signature)) {
			System.out.println("A assinatura do ficheiro: "+ filename + " Foi Verificada: OK");
		} else {
			System.out.println("A assinatura do ficheiro: "+ filename + " Foi Verificada: NOK");
		}
		fis.close();
	}
    public static void escreveMAC(String filename ) throws NoSuchAlgorithmException, InvalidKeyException, IOException {
		
  		//Cria fileIn(le o conteudo) e fileOu(escreve o conteudo)
  		FileInputStream fis = new FileInputStream(filename);
  		FileOutputStream fos = new FileOutputStream(filename + ".mac");
  		
  		//especifica a password
  		byte [] password = "1234".getBytes();
  		SecretKeySpec key = new SecretKeySpec(password, "hmacSHA256");
  		
  		
  		//instancia do mac
  		Mac m = Mac.getInstance("hmacSHA256");
  		m.init(key);
  		
  		byte [] b = new byte[16];
  		int i = fis.read(b);
  		
  		//percorre o ficheiro
  		while (i != -1) {
  			m.update(b,0,i);
  			i = fis.read(b);
  		}
  		
  		//calcula o mac
  		byte [] mac  = m.doFinal();
  		
  		fos.write(mac);
  		fos.close();
  		fis.close();
  		
  	}

public static void verificaMAC(String filename) throws NoSuchAlgorithmException, InvalidKeyException, IOException {
		
		try (
				
			FileInputStream fis = new FileInputStream(filename);
			FileInputStream fisMAC = new FileInputStream(filename + ".mac")) {
			
			//especifica a password
			byte [] password = "1234".getBytes();
			SecretKeySpec key = new SecretKeySpec(password, "hmacSHA256");
	
			//instancia do mac
			Mac m = Mac.getInstance("hmacSHA256");
			m.init(key);
			
			byte [] b = new byte[16];
			int i = fis.read(b);
			
			//percorre o ficheiro
			while (i != -1) {
				m.update(b,0,i);
				i = fis.read(b);
			}
			
			//calcula o mac
			byte [] mac  = m.doFinal();
					
			byte [] macToBeVerified = new byte[fisMAC.available()];
			fisMAC.read(macToBeVerified);
			
			String s_mac = Base64.getEncoder().encodeToString(mac);	
			String s_macToBeVerified = Base64.getEncoder().encodeToString(macToBeVerified);
			
			if (s_mac.equals(s_macToBeVerified)) {
				System.out.println("OK");
			} else {
				System.out.println("NOK");
			}
			
		} catch (IllegalStateException e) {
			e.printStackTrace();
		}
		}
}
package client;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.regex.*;

import javax.crypto.*;

public class mySNS {
	
    private static Socket socket;

    
    /**
     * Método principal para iniciar o cliente mySNS.
     * @param args Argumentos da linha de comando.
     */
    public static void main(String[] args) {
    	
        if (args.length < 6 || !args[0].equals("-a")) {
            System.out.println("Uso do comando deve ser: java mySNS -a <serverAddress> -m <doctorUsername> -u <userUsername> [-sc <filenames>] [-sa <filenames>] [-se <filenames>] [-g <filenames>]\nou\nUsage: java mySNS -a <serverAddress> -u <username do utente> -g {<filenames>}+");
            return;
        }

        String serverAddress = args[1];
        String[] addressParts = serverAddress.split(":");
        
        if (addressParts.length != 2) {
            System.out.println("Formato do endereço do servidor invalido, deve ser - hostname:port");
            return;
        }

        String hostname = addressParts[0];
        int port;
        
        try {
            port = Integer.parseInt(addressParts[1]);
        } catch (NumberFormatException e) {
            System.out.println("Porto deve ser um numero inteiro.");
            return;
        }

        try (Socket socket = new Socket(hostname, port)) {
        	
            System.out.println("Conectado ao servidor.");
            String userUsername = args[3];

            if (args.length >= 6 && args[4].equals("-g")) {
                System.out.println("Vale");

                String[] filenames = new String[args.length - 5];
                System.arraycopy(args, 5, filenames, 0, filenames.length);
                int count = 1;

                for (String filename : filenames) {
                    System.out.println("Filename" + count +": " + filename);                    
                    String[] ficheiros = getFilesFromServer(new String[]{filename}, userUsername);
                    metodoG(ficheiros);
                    count +=1;
                }
                                    
            } else if (args.length >= 8) {
            	
                String doctorUsername = args[3];
                String userUsernamee = args[5];
                File medicoFile = new File("keystore." + doctorUsername);
                
                if (!medicoFile.exists()) {
                    System.out.println("Keystore do medico " + doctorUsername + " não existe");
                    return;
                }

                File utenteFile = new File("keystore." + userUsernamee);
                
                if (!utenteFile.exists()) {
                    System.out.println("Keystore do utente" + userUsernamee + " não existe.");
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
                        System.out.println("Comando invalido: " + command);
                }
            } else {
                System.out.println("Comando ou sequência de comandos invalida.");
            }
            
        } catch (UnknownHostException e) {
            System.err.println("Erro na conexão com o servidor: endereço não reconhecido: " + hostname);
        } catch (IOException e) {
            System.err.println("Erro na conexão com o servidor: " + e.getMessage());
        }
    }


    
    /**
     * Método para deletar arquivos cifrados e chaves secretas associadas.
     * 
     * @param filenames   Nomes dos arquivos a serem deletados.
     * @param userUsername  Nome de usuário do usuário.
     */
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
                    System.out.println("Ficheiro " + filename + " não existe. Ignorando...");
                    continue; 
                }
                
                File cifradoFile = new File(filename + ".cifrado");
                
                if (cifradoFile.exists()) {
                    System.out.println("Ficheiro " + cifradoFile.getName() + " ja existe no servidor. Ignorando...");
                    continue; 
                }
               
                File keyFile = new File(filename + ".chave_secreta." + userUsername);
                
                if (keyFile.exists()) {
                    System.out.println("Ficheiro " + keyFile.getName() + " ja existe no servidor. Ignorando...");
                    continue; 
                }
                
                KeyGenerator kg = KeyGenerator.getInstance("AES");
                kg.init(128);
                SecretKey aesKey = kg.generateKey();

                encryptFileWithAES(filename, aesKey);
                encryptAESKeyWithRSA(aesKey, userUsername, filename);
            
                encryptedFiles.add(filename);
            }
            
            sendFilesToServer(encryptedFiles.toArray(new String[0]), userUsername, "0", ".cifado");

        } catch (NoSuchAlgorithmException e) {
            System.err.println("Erro a gerar a chave AES: " + e.getMessage());
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
    	
        for (String filename : filenames) {
        	
            File file = new File(filename);
			
			if (!file.exists()) {
			    System.out.println("O ficheiro " + filename + " não existe localmente. Ignorando...");
			    continue; 
			}

			File signedFile = new File(filename + ".assinado");               
			if (signedFile.exists()) {
			    System.out.println("O ficheiro " + signedFile.getName() + " já existe no servidor. Ignorando...");
			    continue; 
			}

			File signature = new File(filename + ".assinatura." + doctorUsername); // verifica se já foi assinado
			if (signature.exists()) {
			    System.out.println("O ficheiro " + signature.getName() + " já existe no servidor. Ignorando...");
			    continue; 
			}

			signFile(filename, doctorUsername); // assina com a assinatura do filename acima
			sendFilesToServer(new String[]{filename}, userUsername, doctorUsername, ".assinado"); // envia o ficheiro assinado

			System.out.println("O ficheiro " + filename + " foi assinado e enviado para o servidor com sucesso.");
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
		    System.out.println("O ficheiro " + filename + " foi cifrado, assinado e enviado para o servidor com sucesso.");
		}
    }
    
	 /**
     * Método para realizar operações do metodo -se.
     */
	private static void envelopesSeguros(String userUsername, String filename, String doctorUsername) {
		
		KeyGenerator kg;
		try {
			kg = KeyGenerator.getInstance("AES");
			kg.init(128);
	        SecretKey aesKey = kg.generateKey();
	        encryptAESKeyWithRSA(aesKey, userUsername, filename);
	        //Isso pega o ficheiro ciufrado???????
	        //se nao, precisamos fzr um return no cifra p ppoder delcarar uma variavel aqui?
	        //e passar como o filename do Assina?????????????????????
	        signFile(filename, doctorUsername);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Método para realizar operações em uma lista de arquivos.
	 * 
	 * @param filenames Os nomes dos arquivos nos quais as operações serão realizadas.
	 */
    private static void metodoG(String[] filenames) {
    	    	       
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
     * Método para cifrar uma chave AES com uma chave pública RSA e salvar no disco.
     * 
     * @param aesKey       A chave AES a ser cifrada.
     * @param userUsername Nome de usuário do usuário.
     * @param filename     Nome do arquivo onde a chave cifrada será salva.
     */
    private static void encryptAESKeyWithRSA(SecretKey aesKey, String userUsername, String filename) {
        try {
            try (FileOutputStream kos = new FileOutputStream(filename + ".chave_secreta." + userUsername)) {
                FileInputStream kfile = new FileInputStream("keystore." + userUsername);
                KeyStore kstore = KeyStore.getInstance("PKCS12");
                kstore.load(kfile, "123456".toCharArray()); 
                Certificate cert = kstore.getCertificate(userUsername);
                
                Cipher c1 = Cipher.getInstance("RSA");
                c1.init(Cipher.WRAP_MODE, cert);
                byte[] keyEncoded = c1.wrap(aesKey);

                kos.write(keyEncoded);
            }
        } catch (FileNotFoundException e) {
            System.err.println("Arquivo de keystore não encontrado: " + e.getMessage());
        } catch (IOException e) {
            System.err.println("Erro de I/O durante a cifragem: " + e.getMessage());
        } catch (KeyStoreException e) {
            System.err.println("Problema com o armazenamento de chaves: " + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Algoritmo de cifragem  não encontrado: " + e.getMessage());
        } catch (CertificateException e) {
            System.err.println("Problema com o certificado: " + e.getMessage());
        } catch (NoSuchPaddingException e) {
            System.err.println("Preenchimento especificado não encontrado: " + e.getMessage());
        } catch (InvalidKeyException e) {
            System.err.println("Chave inválida para a cifragem: " + e.getMessage());
        } catch (IllegalBlockSizeException e) {
            System.err.println("Tamanho do bloco de dados inválido para a operação: " + e.getMessage());
        }
    }

    /**
     * Método para cifrar um arquivo usando AES e salvar no disco.
     * 
     * @param filename Nome do arquivo a ser cifrado.
     * @param aesKey   A chave AES usada para cifrar o arquivo.
     */
    private static void encryptFileWithAES(String filename, SecretKey aesKey) {
        try {
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
            System.out.println("Ficheiro encriptado: " + filename + " -> " + filename + ".cifrado");
        } catch (FileNotFoundException e) {
            System.err.println("Arquivo não encontrado: " + e.getMessage());
        } catch (IOException e) {
            System.err.println("Erro de I/O durante a cifragem ou gravação do arquivo: " + e.getMessage());
        }
    }

    
    /**
     * Método para obter uma instância do Cipher AES.
     * 
     * @param aesKey A chave AES usada para inicializar o Cipher.
     * @return O objeto Cipher configurado para criptografar com AES.
     */
    private static Cipher getAESCipher(SecretKey aesKey) {
        try {
            Cipher c = Cipher.getInstance("AES");
            c.init(Cipher.ENCRYPT_MODE, aesKey);
            return c;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            System.err.println("Erro ao inicializar o Cipher AES: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Erro inesperado ao inicializar o Cipher AES: " + e.getMessage());
        }
        return null; // Retorna null em caso de falha
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
     * Método para assinar um arquivo com a chave privada do médico.
     * 
     * @param file           Nome do arquivo a ser assinado.
     * @param doctorUsername Nome de usuário do médico.
     */
    private static void signFile(String file, String doctorUsername) {
        try {
            FileInputStream fis = new FileInputStream(file);
            FileOutputStream fos = new FileOutputStream(file + ".assinado");
            try (FileOutputStream fos2 = new FileOutputStream(file + ".assinatura." + doctorUsername)) {
				FileInputStream kfile1 = new FileInputStream("keystore." + doctorUsername); // Ler a keystore
				KeyStore kstore = KeyStore.getInstance("PKCS12");
				kstore.load(kfile1, "123456".toCharArray());
				PrivateKey myPrivateKey = (PrivateKey) kstore.getKey(doctorUsername, "123456".toCharArray());

				Signature s = Signature.getInstance("MD5withRSA");
				s.initSign(myPrivateKey);

				byte[] b = new byte[1024]; // Leitura
				int i = fis.read(b);
				while (i != -1) { // Quando for igual a -1 chegou-se ao fim do ficheiro
				    s.update(b, 0, i);
				    fos.write(b, 0, i);
				    i = fis.read(b); // Leitura
				}
				byte[] signature2 = s.sign();

				fos.write(s.sign());
				fos2.write(signature2);
			}

            fos.close();
            fis.close();
        } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException | UnrecoverableKeyException | InvalidKeyException | SignatureException e) {
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
    
    
    /**
     * Método para enviar arquivos para o servidor.
     * 
     * @param filenames     Nomes dos arquivos a serem enviados.
     * @param userUsername  Nome de usuário do usuário.
     * @param doctorUsername Nome de usuário do médico (se aplicável).
     * @param extensao      Extensão dos arquivos a serem enviados.
     */
    private static void sendFilesToServer(String[] filenames, String userUsername, String doctorUsername, String extensao) {
        
    	try {
            ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());
            
            
            outStream.writeObject(userUsername);
            
            outStream.writeObject(false);
           
            
     
            for (String filename : filenames) {
             
                File Ficheiro = new File(filename + extensao);
                Long fileSize = Ficheiro.length();
                outStream.writeObject(fileSize); 
                outStream.writeObject(filename + extensao); 
                
                try (BufferedInputStream FicheiroB = new BufferedInputStream(new FileInputStream(Ficheiro))) {
                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = FicheiroB.read(buffer, 0, 1024)) > 0) {
                        outStream.write(buffer, 0, bytesRead);
                    }
                }
                
                if(doctorUsername.equals("0")) {
                	
                	 // Send .key file
                    File keyFile = new File(filename + ".chave_secreta." + userUsername);
                    fileSize = keyFile.length();
                    outStream.writeObject(fileSize); 
                    outStream.writeObject(filename + ".chave.secreta." + userUsername); 
                    
                    try (BufferedInputStream keyFileB = new BufferedInputStream(new FileInputStream(keyFile))) {
                        byte[] buffer = new byte[1024];
                        int bytesRead;
                        while ((bytesRead = keyFileB.read(buffer, 0, 1024)) > 0) {
                            outStream.write(buffer, 0, bytesRead);
                        }
                    }
                	                	
                }
                
                else{
                	
                	File assinaturaFile = new File(filename+".assinatura."+ doctorUsername);
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
            outStream.flush(); // 'Flush' da stream para assegurar que todos os dados foram enviados

            
            Boolean acknowledgment = (Boolean) inStream.readObject();
            System.out.println("Reconhecimento do servidor: " + acknowledgment);

            
            inStream.close();
            outStream.close();

            
            socket.close();
            System.out.println("Conexão fechada.");

            }} catch (IOException | ClassNotFoundException e) {
            System.err.println("Erro a enviar ficheiros para o servidor: " + e.getMessage());
        }
    }
        
    /**
     * Método para receber arquivos do servidor.
     * 
     * @param filenames     Nomes dos arquivos a serem recebidos.
     * @param userUsername  Nome de usuário do usuário.
     */
    private static String[] getFilesFromServer(String[] filenames, String userUsername) {
    	
    	List<String> receivedFiles = new ArrayList<>();
    	
        try {
            try (ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
                 ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream())) {
                
                outStream.writeObject(userUsername);   
                outStream.writeObject(true);
                
                outStream.writeObject(filenames.length);

                for (String filename : filenames) {
                    outStream.writeObject(filename);
                    System.out.println("Envie o nome do ficheiro.");
                 
                    int tamanho = (int) inStream.readObject();
                    System.out.println("Receba o nome do ficheiro.");
                    
                    for(int i=0; i<tamanho; i++){
                        String name = (String)inStream.readObject();
                        long fileSize = (long) inStream.readObject();
                        System.out.println("Receba o tamanho do ficheiro.");
                        
                        if (fileSize == -1) {
                            System.out.println("Ficheiro " + filename + " não encontrado no servidor.");
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
                                System.out.println("Ficheiro encriptado " + name + " recebido do servidor.");
                                
                                receivedFiles.add(name);
                                System.out.println("Ficheiro encriptado: " + name + " adicionado a lista" + receivedFiles);
                            }
                        } else {
                            System.out.println("Tamanho do ficheiro é 0 para o ficheiro: " + name);
                        }
                    }
                }
            }
        } catch (IOException | ClassNotFoundException e) {
            System.err.println("Erro a receber ficheiros do servidor: " + e.getMessage());
        }
        
        return receivedFiles.toArray(new String[0]);
    }
}
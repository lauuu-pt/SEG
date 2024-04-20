package server;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.List;

public class mySNSServer {
	/*Membros do grupo:
	Laura Tomás (58641)
	Maria Beatriz Guerreiro (58643)
	Maria Rita Gonçalves (58659)*/
	
	/**
     * Método principal para iniciar o servidor mySNS.
     * @param args Argumentos da linha de comando.
     */
    public static void main(String[] args) {
        System.out.println("Servidor aberto");
        var server = new mySNSServer();
        server.startServer();
    }

    
    /**
     * Método para iniciar o servidor.
     */
    public void startServer(){
        try (var sSoc = new ServerSocket(23456)) {
            while (true) {
                try {
                    var inSoc = sSoc.accept();
                    var newServerThread = new ServerThread(inSoc);
                    newServerThread.start();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        } catch (IOException e1) {
			e1.printStackTrace();
		}
    }

    
    /**
     * Classe interna que implementa uma thread do servidor para cada cliente.
     */
    class ServerThread extends Thread {
        private Socket socket;

        
        /**
         * Construtor da classe ServerThread.
         * @param inSoc Socket para a conexão do cliente.
         */
        ServerThread(Socket inSoc) {
            socket = inSoc;
            System.out.println("Thread do servidor para cada cliente");
        }

        
        /**
         * Método que executa a thread do servidor.
         */
        public void run() {
            try (var outStream = new ObjectOutputStream(socket.getOutputStream());
                 var inStream = new ObjectInputStream(socket.getInputStream())) {

                String user = null;
                Boolean bool = null;
                
                try {
                    user = (String) inStream.readObject();
                    bool = (Boolean) inStream.readObject();
                    System.out.println("Thread: depois de receber o utilizador");
                } catch (ClassNotFoundException e1) {
                    e1.printStackTrace();
                }
                //outStream.writeObject(true); 
                
                if(!bool) {
	                
	                var userDirectory = new File("/home/aluno-di/eclipse-workspace/SEG/src/server", user);
	                System.out.println("Diretorio do utilizador: " + userDirectory.getAbsolutePath());
	
	                if (!userDirectory.exists()) {
	                	System.out.println("Diretorio do utilizador: " + userDirectory.getAbsolutePath());
	
	                	
	                    if (userDirectory.mkdirs()) {
	                        System.out.println("Criado um diretorio para o utilizador: " + user);
	                    } else {
	                        System.out.println("Erro a criar diretorio: " + user);
	                    }
	                }
	
	                boolean allFilesReceived = true; 
	
	                
	                try {
	                	
	                	while (true) {
	                	    Long fileSize = (Long) inStream.readObject();
	                	    if (fileSize == -1) {
	                	        System.out.println("O cliente acabou de enviar os ficheiros.");
	                	        break;
	                	    }
	                	    
	                	    String filename = (String) inStream.readObject();
	                	    
	                	
	                	    
	                	    var outputFile = new File(userDirectory, filename);
	                	    try (var outFileStream = new FileOutputStream(outputFile);
	                	         var outFile = new BufferedOutputStream(outFileStream)) {
	                	        byte[] buffer = new byte[1024];
	                	        int bytesRead;
	                	        long remainingBytes = fileSize;
	                	        while (remainingBytes > 0 && (bytesRead = inStream.read(buffer, 0, (int) Math.min(buffer.length, remainingBytes))) != -1) {
	                	            outFile.write(buffer, 0, bytesRead);
	                	            remainingBytes -= bytesRead;
	                	        }
	                	    } catch (IOException e) {
	                	        e.printStackTrace();
	                	        allFilesReceived = false;
	                	    }
	
	                	    System.out.println("Fim do ficheiro: " + filename);
	                	}
	
	
	                } catch (EOFException e) {
	                
	                    System.err.println("Cliente desconectou do servidor.");
	                    allFilesReceived = false; 
	                } catch (ClassNotFoundException e1) {
	                    e1.printStackTrace();
	                    allFilesReceived = false; 
	                }
	
	                
	                outStream.writeObject(allFilesReceived); 
	                System.out.println("Transferencia dos ficheiros do servidor reconhecida: " + allFilesReceived);
                } else {
                	System.out.println("aqui");
                	int fileCount = inStream.readInt();
                    System.out.println("Client will send " + fileCount + " files.");
                    List<String> existingFiles = new ArrayList<>();
                    List<File> FilesServer = new ArrayList<File>();
                    for (int i = 0; i < fileCount; i++) {
                        // Read the filename from the client
                        String filename = (String) inStream.readObject();
                        System.out.println("Received filename: " + filename);
                    // Check if any file on the server starts with the received filename
                        
                    File serverDirectory = new File("/home/aluno-di/eclipse-workspace/SEG/src/server", user);
                    File[] filesInDirectory = serverDirectory.listFiles();
                    if (filesInDirectory != null) {
                        for (File file : filesInDirectory) {
                            if (file.exists() && file.isFile() && file.getName().startsWith(filename)) {
                                existingFiles.add(file.getName());
                                FilesServer.add(file);
                                
                            }
                        }
                    }
                }

                // Inform the client about the filenames that already exist on the server
                //ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
                System.out.println(existingFiles);
                System.out.println("no files: "+existingFiles.size());
                //int existingFilesSize=existingFiles.size();
                int existingFileSize = existingFiles.size();
                outStream.writeObject(existingFileSize); // Send the count of existing files
                outStream.flush();
                for(int j =0; j<existingFileSize; j++) {
                	File ficheiro=FilesServer.get(j);
                	outStream.writeObject(ficheiro.getName());
                	outStream.writeObject(ficheiro.length());
                	
                	 try (BufferedInputStream cifradoFileB = new BufferedInputStream(new FileInputStream(ficheiro))) {
                         byte[] buffer = new byte[1024];
                         int bytesRead;
                         while ((bytesRead = cifradoFileB.read(buffer, 0, 1024)) > 0) {
                        	 outStream.write(buffer, 0, bytesRead);
                         }
                         System.out.println("ficheiro "+ficheiro.getName()+" enviado");
                     }
                	 outStream.flush();
                }

               
                    
                }}catch (IOException e) {
	                System.err.println("Erro na comunicação com o cliente: " + e.getMessage());
	                if (e instanceof EOFException) {
	                    System.err.println("O cliente encerrou abruptamente a conexão.");
	                } else if (e instanceof SocketException) {
	                    System.err.println("Erro de socket: " + e.getMessage());
	                }
	            } catch (ClassNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} finally {
	                try {
	                    socket.close();
	                    System.out.println("Conexão com o cliente encerrada.");
	                } catch (IOException e) {
	                    System.err.println("Erro ao fechar o socket: " + e.getMessage());
	                }
	            }
            
        
    }
    }}
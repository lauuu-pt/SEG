package projeto.server;

import java.io.*;
import java.net.*;
import java.util.*;

public class mySNSServer {
    public static void main(String[] args) {
    	
        System.out.println("Servidor: main");
		var server = new mySNSServer();
		server.startServer();
    }
    
    public void startServer() {
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
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    class ServerThread extends Thread {
    
        private Socket socket;
        ServerThread(Socket inSoc) {
            socket = inSoc;
            System.out.println("Thread do servidor para cada cliente");
        }
        
        public void run() {
        	
            try (var outStream = new ObjectOutputStream(socket.getOutputStream());
                 var inStream = new ObjectInputStream(socket.getInputStream())) {

                String user = null;
                Boolean bool = null;
                
                try {
                
                    user = (String) inStream.readObject();
                    bool = (Boolean) inStream.readObject();
                    
                    System.out.println("Thread: depois de receber  o usuário");
                } catch (ClassNotFoundException e1) {
                    e1.printStackTrace();
                }
                outStream.writeObject(true); // Sending acknowledgment to the client
                
                if(!bool) {
                    // Create a directory based on the username
                    var userDirectory = new File("/home/aluno-di/eclipse-workspace/SEG/src/projeto/server", user); // Assuming "user_files" is the parent directory
                    System.out.println("User directory path: " + userDirectory.getAbsolutePath());
    
                    if (!userDirectory.exists()) {
                        System.out.println("User directory path: " + userDirectory.getAbsolutePath());

                        if (userDirectory.mkdirs()) {
                            System.out.println("Created directory for user: " + user);
                        } else {
                            System.out.println("Failed to create directory for user: " + user);
                        }
                    }
    
                    boolean allFilesReceived = true; // Track if all files were received successfully
    
                    // Receive and store files in the user directory
                    try {
                    	
                        while (true) {
                            Long fileSize = (Long) inStream.readObject();
                            if (fileSize == -1) { // End of file transfer
                                System.out.println("Client finished sending files.");
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
                                allFilesReceived = false; // Mark that not all files were received successfully
                            }
    
                            System.out.println("End of file: " + filename);
                        }
    
    
                    } catch (EOFException e) {
                        // Client disconnected prematurely
                        System.err.println("Client disconnected before all files were received.");
                        allFilesReceived = false; // Mark that not all files were received successfully
                    } catch (ClassNotFoundException e1) {
                        e1.printStackTrace();
                        allFilesReceived = false; // Mark that not all files were received successfully
                    }
    
                    // Send acknowledgment based on the status of file reception
                    outStream.writeObject(allFilesReceived); // Sending acknowledgment to the client
                    System.out.println("Server acknowledges successful file transfer: " + allFilesReceived);
                } else {
    
                    int lenFicheiros = (int)inStream.readObject();
                    for(int i = 0; i < lenFicheiros; i++){
                        List<File> FilesServer = new ArrayList<File>();
                        String nomeFicheiro = (String) inStream.readObject();
                        var Diretorio  = new File("/home/aluno-di/eclipse-workspace/SEG/src/projeto/server", user);
                        File[] files = Diretorio.listFiles();
                        
                        // Itera sobre os arquivos e verifica se começam com o padrão
                        if (files != null) {
                            for (File file : files) {
                                if (file.isFile() && file.getName().startsWith(nomeFicheiro)){
                                    FilesServer.add(file);
                                }
                            }
                            
                            outStream.writeObject(FilesServer.size());
                            
                            for(int j =0; j<FilesServer.size(); j++) {
                                outStream.writeObject(FilesServer.get(j).getName());
                                outStream.writeObject(FilesServer.get(j).length());
                                
                                try (BufferedInputStream cifradoFileB = new BufferedInputStream(new FileInputStream(FilesServer.get(j)))) {
                                    byte[] buffer = new byte[1024];
                                    int bytesRead;
                                    while ((bytesRead = cifradoFileB.read(buffer, 0, 1024)) > 0) {
                                        outStream.write(buffer, 0, bytesRead);
                                    }
                                }
                            }
                        } else {
                            System.out.println("O caminho especificado não é um diretório.");
                        }
                    }
                                      
                }
            } catch (IOException e) {
                System.err.println("Erro na comunicação com o cliente: " + e.getMessage());
                if (e instanceof EOFException) {
                    System.err.println("O cliente encerrou abruptamente a conexão.");
                } else if (e instanceof SocketException) {
                    System.err.println("Erro de soquete: " + e.getMessage());
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
    }	
}
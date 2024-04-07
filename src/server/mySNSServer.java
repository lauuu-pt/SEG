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
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class mySNSServer {

    public static void main(String[] args) throws IOException {
        System.out.println("Servidor: main");
        var server = new mySNSServer();
        server.startServer();
    }

    public void startServer() throws IOException {
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
                outStream.writeObject(true); 
                
                if(!bool) {
	                
	                var userDirectory = new File("/home/aluno-di/eclipse-workspace/SEG/src/server", user);
	                System.out.println("User directory path: " + userDirectory.getAbsolutePath());
	
	                if (!userDirectory.exists()) {
	                	System.out.println("User directory path: " + userDirectory.getAbsolutePath());
	
	                	
	                    if (userDirectory.mkdirs()) {
	                        System.out.println("Created directory for user: " + user);
	                    } else {
	                        System.out.println("Failed to create directory for user: " + user);
	                    }
	                }
	
	                boolean allFilesReceived = true; 
	
	                
	                try {
	                	
	                	while (true) {
	                	    Long fileSize = (Long) inStream.readObject();
	                	    if (fileSize == -1) {
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
	                	        allFilesReceived = false;
	                	    }
	
	                	    System.out.println("End of file: " + filename);
	                	}
	
	
	                } catch (EOFException e) {
	                
	                    System.err.println("Client disconnected before all files were received.");
	                    allFilesReceived = false; 
	                } catch (ClassNotFoundException e1) {
	                    e1.printStackTrace();
	                    allFilesReceived = false; 
	                }
	
	                
	                outStream.writeObject(allFilesReceived); 
	                System.out.println("Server acknowledges successful file transfer: " + allFilesReceived);
                } else {
                	try {
                		var userDirectory = new File("/home/aluno-di/eclipse-workspace/SEG/src/server", user);
                		String filename = (String) inStream.readObject();
                		File file = new File(filename);
                		System.out.println("AAAAAAAAAAAAAAAAA");
                			String prefix = filename;
                			List<File> filesFound = new ArrayList<>();
                			File[] files = userDirectory.listFiles();
                			System.out.println("BBBBBBBBBBBB");
                			for (File f : files) {
                		        
                		        if (f.getName().startsWith(prefix)) {
                		            
                		            filesFound.add(f);
                		            System.out.println("CCCCCCCCCCCCC");
                		        }
                		    }
                			for (File fi: filesFound) {
                			    
                			    outStream.writeObject(fi.getName());
                			    System.out.println(fi.getName());
                			    
                			    outStream.writeObject(fi.length());
                			    System.out.println(fi.length());
                			    
                			    try (BufferedInputStream myFileB = new BufferedInputStream(new FileInputStream(fi))) {
                			        byte[] buffer = new byte[1024];
                			        int bytesRead;
                			        while ((bytesRead = myFileB.read(buffer)) != -1) {
                			            outStream.write(buffer, 0, bytesRead);
                			            System.out.println("FFFFFFFFFFFF");
                			        }
                			    }
                			}

                			outStream.close();
                			inStream.close();
            		    
                	} catch(Exception e ){
                		
                	}
                }
	            } catch (IOException e) {
	                System.err.println("Erro na comunicação com o cliente: " + e.getMessage());
	                if (e instanceof EOFException) {
	                    System.err.println("O cliente encerrou abruptamente a conexão.");
	                } else if (e instanceof SocketException) {
	                    System.err.println("Erro de soquete: " + e.getMessage());
	                }
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
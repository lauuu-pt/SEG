package projeto.server;
import java.io.BufferedOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.HashSet;
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
                String passwd = null;
                try {
                    user = (String) inStream.readObject();
                    passwd = (String) inStream.readObject();
                    System.out.println("Thread: depois de receber a senha e o usuário");
                } catch (ClassNotFoundException e1) {
                    e1.printStackTrace();
                }
                outStream.writeObject(true); // Sending acknowledgment to the client

                // Create a directory based on the username
                var userDirectory = new File("/home/aluno-di/eclipse-workspace/SEG/src/projeto/server", user); // Assuming "user_files" is the parent directory
                System.out.println("User directory path: " + userDirectory.getAbsolutePath());

                if (!userDirectory.exists()) {
                	System.out.println("User directory path: " + userDirectory.getAbsolutePath());

                	System.out.println("wwwwwwwwwwwwwwwwwwwwwww");
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
    }
}

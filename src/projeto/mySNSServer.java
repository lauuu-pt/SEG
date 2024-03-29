package projeto;

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

public class mySNSServer {

    public static void main(String[] args) throws IOException {
        System.out.println("servidor: main");
        mySNSServer server = new mySNSServer();
        server.startServer();
    }

	public void startServer() throws IOException {
    	ServerSocket sSoc = null; 
    	
        try {
        	sSoc = new ServerSocket(23456);
        	} catch (IOException e) {
    			System.err.println(e.getMessage());
    			System.exit(-1);
    		}
            while (true) {
                try {
                    Socket inSoc = sSoc.accept();
                    ServerThread newServerThread = new ServerThread(inSoc);
                    newServerThread.start();
                    
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        
        //sSoc.close();
    }
    
    class ServerThread extends Thread {

        private Socket socket=null;

        ServerThread(Socket inSoc) {
            socket = inSoc;
            System.out.println("thread do server para cada cliente");
        }

        public void run() {
            try (ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
                 ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream())) {

                String user = null;
                String passwd = null;
                try {
					user = (String)inStream.readObject();
					passwd = (String)inStream.readObject();
					System.out.println("thread: depois de receber a password e o user");
				}catch (ClassNotFoundException e1) {
					e1.printStackTrace();
				}
                if (user.length() != 0){
					outStream.writeObject( (Boolean) true);
				}
				else {
					outStream.writeObject( (Boolean) false);
				}
                // Create a directory based on the username
                File userDirectory = new File(user);
                if (!userDirectory.exists()) {
                    if (userDirectory.mkdirs()) {
                        System.out.println("Created directory for user: " + user);
                    } else {
                        System.out.println("Failed to create directory for user: " + user);
                    }
                }

                // Receive and store files in the user directory
                try {
                    while (true) {
                        System.out.println("Start of file");
                        Long fileSize = (Long) inStream.readObject();
                        String filename = (String) inStream.readObject();

                        File outputFile = new File(userDirectory, filename);
                        try (FileOutputStream outFileStream = new FileOutputStream(outputFile);
                             BufferedOutputStream outFile = new BufferedOutputStream(outFileStream)) {

                            byte[] buffer = new byte[1024];
                            int bytesRead;
                            long remainingBytes = fileSize;
                            while (remainingBytes > 0 && (bytesRead = inStream.read(buffer, 0, (int) Math.min(buffer.length, remainingBytes))) != -1) {
                                outFile.write(buffer, 0, bytesRead);
                                remainingBytes -= bytesRead;
                            }
                        } catch (IOException e) {
                            e.printStackTrace();
                        }

                        System.out.println("End of file: " + filename);
                    }
                } catch (EOFException e) {
                    // End of file transfer
                    System.out.println("Client finished sending files.");
                } catch (ClassNotFoundException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}

                
                
                
            } catch (IOException e) {
                System.err.println("Erro na comunicação com o cliente: " + e.getMessage());
                // Se desejar, você pode adicionar detalhes específicos para diferentes tipos de exceções de E/S.
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

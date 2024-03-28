package projeto;

import java.io.BufferedOutputStream;
import java.io.EOFException;
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
        	sSoc = new ServerSocket(23456);{
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
        } catch (IOException e) {
            System.err.println("Erro ao iniciar o servidor: " + e.getMessage());
        }
        //sSoc.close();
    }
    
    class ServerThread extends Thread {

        private final Socket socket;

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
                    user = (String) inStream.readObject();
                    passwd = (String) inStream.readObject();
                    System.out.println("thread: depois de receber a password e o user");
                } catch (ClassNotFoundException e1) {
                    e1.printStackTrace();
                }

              /*  if (user != null && !user.isEmpty()) {
                    outStream.writeObject(true);
                } else {
                    outStream.writeObject(false);
                }

                System.out.println("inicio de ficheiro");
                try (FileOutputStream outFileStream = new FileOutputStream("ficheiro.pdf");
                     BufferedOutputStream outFile = new BufferedOutputStream(outFileStream)) {

                    Long fileSize = (Long) inStream.readObject();
                    byte[] buffer = new byte[1024];
                    int x;
                    int temp = fileSize.intValue();
                    while (temp > 0 && (x = inStream.read(buffer, 0, Math.min(1024, temp))) != -1) {
                        outFile.write(buffer, 0, x);
                        temp -= x;
                    }
                } catch (ClassNotFoundException e) {
                    e.printStackTrace();
                }

                System.out.println("fim do ficheiro");*/
                
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

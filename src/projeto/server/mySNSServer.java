package projeto.server;

import java.io.*;
import java.net.*;
import java.util.*;

public class mySNSServer {
    public static void main(String[] args) {
    	
        System.out.println("Servidor aberto!");
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
                } catch (IOException e) { // Exceção para lidar com problemas de Input/Output (I/O).
                    e.printStackTrace();
                }
            }
        } catch (IOException e) { // Exceção para lidar com problemas de Input/Output (I/O).
            e.printStackTrace();
        }
    }
    
    class ServerThread extends Thread {
    
        private Socket socket;
        ServerThread(Socket inSoc) {
            socket = inSoc;
            System.out.println("Thread do servidor para cada cliente.");
        }
        
        public void run() {
        	
            try (var outStream = new ObjectOutputStream(socket.getOutputStream());
                 var inStream = new ObjectInputStream(socket.getInputStream())) {

                String user = null;
                Boolean bool = null;
                
                try {
                
                    user = (String) inStream.readObject();
                    bool = (Boolean) inStream.readObject();
                    
                    System.out.println("Thread - depois de receber  o usuário");
                    
                } catch (ClassNotFoundException e1) { // Lida com exceção no caso da classe não existir.
                    e1.printStackTrace();
                }
                outStream.writeObject(true);
                
                if(!bool) {
                	
                    // Cria um diretorio baseado no username dado pela variavel "user".
                    var userDirectory = new File("/home/aluno-di/eclipse-workspace/SEG/src/projeto/server", user);
                    System.out.println("Diretorio do utilizador: " + userDirectory.getAbsolutePath());
    
                    if (!userDirectory.exists()) { // Se o diretorio não existir
                        System.out.println("Diretorio do utilizador: " + userDirectory.getAbsolutePath());
                        
                        if (userDirectory.mkdirs()) { // Cria diretorio para o utilizador.
                            System.out.println("Criado um diretorio para o utilizador " + user);
                            
                        } else {
                            System.out.println("Não foi possivel criar o diretorio para o utilizador " + user);
                        }
                    }
    
                    boolean allFilesReceived = true; // Verifica se todos os ficheiros foram recebidos com sucesso.
    
                    // Recebe e guarda os ficheiros no diretorio do utilizador.
                    try {
                        while (true) {
                            Long fileSize = (Long) inStream.readObject();
                            
                            if (fileSize == -1) { // Fim da transferência de ficheiros cliente-servidor.
                                System.out.println("Cliente acabou de enviar os ficheiros.");
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
                            } catch (IOException e) { // Exceção para lidar com problemas de Input/Output (I/O).
                                e.printStackTrace();                                 
                                allFilesReceived = false; // Nem todos os ficheiros foram recebidos com sucesso.
                            }
    
                            System.out.println("Fim do ficheiro " + filename);
                        }
    
    
                    } catch (EOFException e) {
                    	
                        // Cliente desconectou abruptamente
                        System.err.println("Cliente desconectado antes de todos os ficheiros terem sido recebidos.");
                        
                        allFilesReceived = false; // Nem todos os ficheiros foram recebidos com sucesso.
                    } catch (ClassNotFoundException e1) {
                        e1.printStackTrace();
                        allFilesReceived = false; // Nem todos os ficheiros foram recebidos com sucesso.
                    }
    
                    // Manda reconhecimento para o cliente que todos os ficheiros foram recebidos.
                    outStream.writeObject(allFilesReceived); 
                    System.out.println("Servidor reconhece que todos os ficheiros foram recebidos? " + allFilesReceived);
                    
                } else {
                    int lenFicheiros = (int)inStream.readObject();
                    for(int i = 0; i < lenFicheiros; i++){
                        List<File> FilesServer = new ArrayList<File>();
                        String nomeFicheiro = (String) inStream.readObject();
                        var Diretorio  = new File("/home/aluno-di/eclipse-workspace/SEG/src/projeto/server", user);
                        File[] files = Diretorio.listFiles();
                        
                        // Itera sobre os arquivos e verifica se começam com o nome do ficheiro
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
                    System.err.println("Erro de socket: " + e.getMessage());
                }
            } catch (ClassNotFoundException e) {
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
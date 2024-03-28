package projeto;

import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;

public class mySNS {

    public static void main(String[] args) throws InterruptedException {
        if (args.length < 2 || !args[0].equals("-a")) {
            System.out.println("Uso: java MySNS -a <serverAddress>");
            return;
        }

        String serverAddress = args[1];
        String[] addressParts = serverAddress.split(":");
        if (addressParts.length != 2) {
            System.out.println("Endereço do servidor inválido. Use o formato: hostname:port");
            return;
        }

        String hostname = addressParts[0];
        int port;
        try {
            port = Integer.parseInt(addressParts[1]);
        } catch (NumberFormatException e) {
            System.out.println("Porto deve ser um número inteiro.");
            return;
        }

        Socket socket = null;
        try {
            System.out.println("Tentando se conectar ao servidor: " + hostname + ":" + port);
            socket = new Socket(hostname, port);
            System.out.println("Conexão bem-sucedida ao servidor: " + hostname + ":" + port);

            // Aqui você pode implementar a lógica para as outras opções fornecidas na linha de comando.
            // Por enquanto, apenas exibiremos o endereço do servidor.

        } catch (UnknownHostException e) {
            System.err.println("Erro ao conectar ao servidor. Endereço do servidor desconhecido: " + hostname);
        } catch (IOException e) {
            System.err.println("Erro ao conectar ao servidor: " + e.getMessage());
        } finally {
            if (socket != null && !socket.isClosed()) {
                try {
                    System.out.println("Fechando conexão com o servidor...");
                    socket.close();
                    System.out.println("Conexão fechada.");
                } catch (IOException e) {
                    System.err.println("Erro ao fechar a conexão: " + e.getMessage());
                }
            }
        }
    }

}

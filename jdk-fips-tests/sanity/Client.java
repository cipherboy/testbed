import java.net.*;
import java.io.*;
import javax.net.ssl.*;

public class Client {

    public static void main(String[] args) throws Exception {
        try {
            SSLSocketFactory factory =
                (SSLSocketFactory)SSLSocketFactory.getDefault();

            if (args.length < 2) {

                String[] cipherSuites = factory.getSupportedCipherSuites();
                System.out.println("Got cipher suites: " + cipherSuites.length);
                for (int i=0; i < cipherSuites.length; i++)
                    System.out.println(cipherSuites[i]);                
                
                System.exit(0);
            }

            SSLSocket socket =
                (SSLSocket)factory.createSocket(args[0], Integer.parseInt(args[1]));
            
            if (args.length == 3) {
                String pickedCipher[] = { args[2] };
                socket.setEnabledCipherSuites(pickedCipher);
            }
            
            socket.addHandshakeCompletedListener(
                new HandshakeCompletedListener() {
                    public void handshakeCompleted(
                            HandshakeCompletedEvent event) {
                        System.out.println("CH:" + event.getCipherSuite());
                    }
                }
                                                 );
            socket.startHandshake();

            PrintWriter out = new PrintWriter(
                                  new BufferedWriter(
                                  new OutputStreamWriter(
                                  socket.getOutputStream())));

            out.println("GET / HTTP/1.0");
            out.println();
            out.flush();
            
            BufferedReader in = new BufferedReader(
                                    new InputStreamReader(
                                    socket.getInputStream()));

            String inputLine;
            while ((inputLine = in.readLine()) != null)
                System.out.println(inputLine);

            in.close();
            out.close();
            socket.close();

        } catch (Exception e) {            
            e.printStackTrace();
            throw e;
        }
    }
}

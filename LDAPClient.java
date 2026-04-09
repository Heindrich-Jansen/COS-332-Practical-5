import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.List;
import java.util.Scanner;

public class LDAPClient {
    private static final String SERVER_IP = "127.0.0.1";
    private static final int PORT = 389;
    private static final String BIND_DN = "cn=admin,dc=prac5,dc=com";
    private static final String BIND_PASS = "admin";
    private static final String BASE_DN = "ou=Planes,dc=prac5,dc=com";

    public static main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter asset name (e.g., Boeing 747): ");
        String assetName = scanner.nextLine().trim();

        try (Socket socket = new Socket(SERVER_IP, PORT);
             InputStream in = socket.getInputStream();
             OutputStream out = socket.getOutputStream()) {

            System.out.println("\n[+] Connected to LDAP Server at " + SERVER_IP + ":" + PORT);

            // ==========================================
            // STEP 1: SEND BIND REQUEST (Authentication)
            // ==========================================
            // BindRequest ::= [APPLICATION 0] SEQUENCE { version(3), name, authentication }
            byte[] bindOp = BER.encodeApplication(0, true, BER.encodeSequence(List.of(
                    BER.encodeInteger(3), // version
                    BER.encodeOctetString(BIND_DN), // name
                    BER.encodeContextSpecific(0, false, BIND_PASS.getBytes()) // authentication
            )));

            // Message Envelope: SEQUENCE { messageID(1), protocolOp }
            byte[] bindMessage = BER.encodeSequence(List.of(BER.encodeInteger(1), bindOp));
            out.write(bindMessage);
            out.flush();

            // Read Bind Response
            BER.BerValue bindResponseMsg = BER.decode(in);
            List<BER.BerValue> bindSeq = bindResponseMsg.asSequence();
            BER.BerValue bindProtocolOp = bindSeq.get(1); // [APPLICATION 1] BindResponse

            // The resultCode is the first element in the BindResponse sequence. 0 = Success.
            int resultCode = bindProtocolOp.asSequence().get(0).value[0];
            if (resultCode != 0) {
                System.out.println("[-] Bind failed with result code: " + resultCode);
                return;
            }
            System.out.println("[+] Bind successful!");

            }

    }
}
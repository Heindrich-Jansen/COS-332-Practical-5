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

public static void main(String[] args) {
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
            // BindRequest ::= [APPLICATION 0] IMPLICIT SEQUENCE
            ByteArrayOutputStream bindContent = new ByteArrayOutputStream();
            bindContent.write(BER.encodeInteger(3)); // version
            bindContent.write(BER.encodeOctetString(BIND_DN)); // name
            bindContent.write(BER.encodeContextSpecific(0, false, BIND_PASS.getBytes())); // authentication
            
            byte[] bindOp = BER.encodeApplication(0, true, bindContent.toByteArray());

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

            // ==========================================
            // STEP 2: SEND SEARCH REQUEST
            // ==========================================
            ByteArrayOutputStream filterContent = new ByteArrayOutputStream();
            filterContent.write(BER.encodeOctetString("cn"));
            filterContent.write(BER.encodeOctetString(assetName));
            byte[] filter = BER.encodeContextSpecific(3, true, filterContent.toByteArray());

            byte[] attributes = BER.encodeSequence(List.of(BER.encodeOctetString("description")));

            // SearchRequest ::= [APPLICATION 3] IMPLICIT SEQUENCE
            ByteArrayOutputStream searchContent = new ByteArrayOutputStream();
            searchContent.write(BER.encodeOctetString(BASE_DN));
            searchContent.write(BER.encodeInteger(2)); // Scope: 2 = wholeSubtree
            searchContent.write(BER.encodeInteger(0)); // DerefAliases
            searchContent.write(BER.encodeInteger(0)); // SizeLimit
            searchContent.write(BER.encodeInteger(0)); // TimeLimit
            searchContent.write(BER.encodeBoolean(false)); // TypesOnly
            searchContent.write(filter);
            searchContent.write(attributes);

            byte[] searchOp = BER.encodeApplication(3, true, searchContent.toByteArray());

            // Message Envelope: SEQUENCE { messageID(2), protocolOp }
            byte[] searchMessage = BER.encodeSequence(List.of(BER.encodeInteger(2), searchOp));
            out.write(searchMessage);
            out.flush();
            System.out.println("[+] Search request sent for: " + assetName);

            // ==========================================
            // STEP 3: READ AND UNPACK SEARCH RESPONSES
            // ==========================================
            boolean found = false;

            while (true) {
                BER.BerValue msg = BER.decode(in);
                List<BER.BerValue> seq = msg.asSequence();
                BER.BerValue protocolOp = seq.get(1);

                if (protocolOp.tagClass == BER.TAG_CLASS_APPLICATION) {
                    if (protocolOp.tagNumber == 5) { 
                        // SearchResultDone
                        break; 
                    } 
                    else if (protocolOp.tagNumber == 4) { 
                        // SearchResultEntry
                        List<BER.BerValue> entryParts = protocolOp.asSequence();
                        List<BER.BerValue> attrsList = entryParts.get(1).asSequence();

                        for (BER.BerValue attr : attrsList) {
                            List<BER.BerValue> attrParts = attr.asSequence(); 
                            String type = attrParts.get(0).asString();
                            
                            if ("description".equalsIgnoreCase(type)) {
                                List<BER.BerValue> vals = attrParts.get(1).asSequence(); 
                                String speed = vals.get(0).asString();
                                
                                System.out.println("-------------------------------------------------");
                                System.out.println(" SUCCESS: The maximum speed of " + assetName + " is " + speed + " km/h");
                                System.out.println("-------------------------------------------------");
                                found = true;
                            }
                        }
                    }
                }
            }

            if (!found) {
                System.out.println("[-] Asset '" + assetName + "' was not found or has no speed description.");
            }

            // ==========================================
            // STEP 4: SEND UNBIND REQUEST (Graceful Disconnect)
            // ==========================================
            byte[] unbindOp = BER.encodeApplication(2, false, new byte[0]);
            byte[] unbindMessage = BER.encodeSequence(List.of(BER.encodeInteger(3), unbindOp));
            out.write(unbindMessage);
            out.flush();
            System.out.println("[+] Unbind request sent. Safely disconnecting...");

        } catch (Exception e) {
            System.out.println("[-] Error communicating with LDAP server:");
            e.printStackTrace();
        }
    }
}
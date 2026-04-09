import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class LDAPClient {
    private static final String SERVER_IP = "127.0.0.1";
    private static final int PORT = 389;
    private static final String BIND_DN = "cn=admin,dc=prac5,dc=com";
    private static final String BIND_PASS = "admin";
    private static final int LDAP_VERSION = 3;

    // Control ::= SEQUENCE { controlType LDAPOID, criticality BOOLEAN DEFAULT FALSE, controlValue OCTET STRING OPTIONAL }
    static final class LdapControl {
        final String controlType;
        final boolean criticality;
        final byte[] controlValue;

        LdapControl(String controlType, boolean criticality, byte[] controlValue) {
            this.controlType = controlType;
            this.criticality = criticality;
            this.controlValue = controlValue;
        }
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Press Enter to send simple BindRequest: ");
        scanner.nextLine();

        try (Socket socket = new Socket(SERVER_IP, PORT);
             InputStream in = socket.getInputStream();
             OutputStream out = socket.getOutputStream()) {

            System.out.println("\n[+] Connected to LDAP Server at " + SERVER_IP + ":" + PORT);

            // ASN.1 envelope: LDAPMessage ::= SEQUENCE { messageID, protocolOp, controls OPTIONAL }
            byte[] bindOp = encodeSimpleBindRequest(BIND_DN, BIND_PASS);
            byte[] bindMessage = encodeLdapMessage(1, bindOp, List.of());
            out.write(bindMessage);
            out.flush();

            // Read Bind Response
            BER.BerValue bindResponseMsg = BER.decode(in);
            int resultCode = parseBindResultCode(bindResponseMsg);
            if (resultCode != 0) {
                System.out.println("[-] Bind failed with result code: " + resultCode);
                return;
            }
            System.out.println("[+] Bind successful!");
        } catch (Exception e) {
            System.out.println("[-] LDAP client failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // BindRequest ::= [APPLICATION 0] SEQUENCE { version INTEGER, name LDAPDN, authentication CHOICE { simple [0] OCTET STRING } }
    private static byte[] encodeSimpleBindRequest(String bindDn, String password) throws IOException {
        byte[] bindRequestSequence = BER.encodeSequence(List.of(
                BER.encodeInteger(LDAP_VERSION),
                BER.encodeOctetString(bindDn),
                BER.encodeContextSpecific(0, false, password.getBytes(StandardCharsets.UTF_8))
        ));
        return BER.encodeApplication(0, true, bindRequestSequence);
    }

    // LDAPMessage ::= SEQUENCE { messageID MessageID, protocolOp CHOICE, controls [0] Controls OPTIONAL }
    private static byte[] encodeLdapMessage(int messageId, byte[] protocolOp, List<LdapControl> controls) throws IOException {
        List<byte[]> envelopeFields = new ArrayList<>();
        envelopeFields.add(BER.encodeInteger(messageId));
        envelopeFields.add(protocolOp);

        if (controls != null && !controls.isEmpty()) {
            byte[] controlsSequence = encodeControls(controls);
            // Optional controls are context-specific [0], constructed.
            envelopeFields.add(BER.encodeContextSpecific(0, true, controlsSequence));
        }

        return BER.encodeSequence(envelopeFields);
    }

    // Controls ::= SEQUENCE OF control Control
    private static byte[] encodeControls(List<LdapControl> controls) throws IOException {
        List<byte[]> encodedControls = new ArrayList<>();
        for (LdapControl control : controls) {
            List<byte[]> fields = new ArrayList<>();
            fields.add(BER.encodeOctetString(control.controlType));
            if (control.criticality) {
                fields.add(BER.encodeBoolean(true));
            }
            if (control.controlValue != null) {
                fields.add(BER.encodeOctetString(control.controlValue));
            }
            encodedControls.add(BER.encodeSequence(fields));
        }
        return BER.encodeSequence(encodedControls);
    }

    private static int parseBindResultCode(BER.BerValue ldapMessage) throws IOException {
        List<BER.BerValue> top = ldapMessage.asSequence();
        if (top.size() < 2) {
            throw new IOException("Malformed LDAPMessage: missing protocolOp");
        }

        BER.BerValue protocolOp = top.get(1);
        if (protocolOp.tagClass != BER.TAG_CLASS_APPLICATION || protocolOp.tagNumber != 1) {
            throw new IOException("Expected BindResponse [APPLICATION 1]");
        }

        List<BER.BerValue> bindResponseFields = BER.decodeAll(new java.io.ByteArrayInputStream(protocolOp.value));
        if (bindResponseFields.isEmpty()) {
            throw new IOException("Malformed BindResponse: missing resultCode");
        }

        return (int) bindResponseFields.get(0).asInteger();
    }

}
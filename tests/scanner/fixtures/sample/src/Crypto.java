import java.security.*;
import javax.crypto.*;

class Crypto {
    void run() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        Signature s = Signature.getInstance("SHA256withECDSA");
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
    }
}

package dev.waxseal.log;

import dev.waxseal.merkle.Hashing;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;

/** Ed25519 key handling. Ed25519 is deterministic, so signing never depends on a random source. */
public final class Keys {

    private static final String ALGORITHM = "Ed25519";

    private Keys() {
    }

    public static KeyPair generate() {
        try {
            return KeyPairGenerator.getInstance(ALGORITHM).generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 is unavailable in this Java runtime", e);
        }
    }

    public static byte[] sign(PrivateKey key, byte[] message) {
        try {
            Signature signature = Signature.getInstance(ALGORITHM);
            signature.initSign(key);
            signature.update(message);
            return signature.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("cannot sign with the given key", e);
        }
    }

    public static boolean verify(PublicKey key, byte[] message, byte[] signatureBytes) {
        try {
            Signature signature = Signature.getInstance(ALGORITHM);
            signature.initVerify(key);
            signature.update(message);
            return signature.verify(signatureBytes);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    public static String encodePublic(PublicKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static PublicKey decodePublic(String base64) {
        try {
            byte[] encoded = Base64.getDecoder().decode(base64.strip());
            return KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(encoded));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("not an Ed25519 public key", e);
        }
    }

    public static String encodePrivate(PrivateKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static PrivateKey decodePrivate(String base64) {
        try {
            byte[] encoded = Base64.getDecoder().decode(base64.strip());
            return KeyFactory.getInstance(ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(encoded));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("not an Ed25519 private key", e);
        }
    }

    /** Short identifier a human can compare out of band before trusting a key. */
    public static String fingerprint(PublicKey key) {
        byte[] digest = Hashing.sha256().digest(key.getEncoded());
        return HexFormat.ofDelimiter(":").formatHex(digest, 0, 8);
    }
}

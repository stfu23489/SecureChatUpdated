package dev.securechatupdated;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Cryptographic utilities for Secure Chat Updated.
 *
 * <h2>Encryption scheme</h2>
 * <ol>
 *   <li>The plaintext is prepended with a millisecond timestamp and a
 *       separator ({@code "<ts>|<plaintext>"}) for replay and expiry
 *       protection.</li>
 *   <li>A 256-bit AES key is derived from the passphrase using PBKDF2-HMAC-SHA256
 *       with a random 4-byte salt and {@value #ITERATIONS} iterations.</li>
 *   <li>The timestamped plaintext is encrypted with AES-GCM (96-bit IV, 128-bit
 *       auth tag).</li>
 *   <li>The binary payload is laid out as:
 *       {@code [4-byte salt][12-byte IV][ciphertext+tag]}.</li>
 *   <li>The payload is Base64-encoded, then optionally compressed to a shorter
 *       string using a custom Base4096 alphabet (pairs of Base64 characters
 *       mapped to a single Unicode code point).</li>
 * </ol>
 *
 * <h2>Replay protection</h2>
 * Incoming ciphertexts are tracked in a bounded LRU set. Duplicates are
 * rejected with {@link DecryptError#REPLAY}. Messages whose embedded timestamp
 * falls outside {@link #CLOCK_SKEW_MS} of the local clock are rejected with
 * {@link DecryptError#EXPIRED}.
 *
 * <p>This class is non-instantiable; all members are static.</p>
 */
public final class SecureChatUpdatedCryptoUtil {

    // -------------------------------------------------------------------------
    // Cipher constants
    // -------------------------------------------------------------------------

    private static final String ALGO       = "AES/GCM/NoPadding";
    private static final int    IV_LEN     = 12;   // 96-bit IV — GCM recommended size
    private static final int    TAG_LEN    = 128;  // GCM authentication tag length in bits
    private static final String KDF        = "PBKDF2WithHmacSHA256";
    private static final int    ITERATIONS = 65536;
    private static final int    KEY_BITS   = 256;
    private static final int    SALT_LEN   = 4;    // bytes; short to keep ciphertext compact

    // -------------------------------------------------------------------------
    // Timestamp / replay constants
    // -------------------------------------------------------------------------

    /** Maximum allowed difference (ms) between a message's timestamp and local clock. */
    private static final long   CLOCK_SKEW_MS = 60_000; // 1 minute

    /** Separator between the timestamp and plaintext inside the encrypted payload. */
    private static final String SEPARATOR     = "|";

    // -------------------------------------------------------------------------
    // Base64 alphabet used as the "source" alphabet for Base4096 compression
    // -------------------------------------------------------------------------

    /** Standard (unpadded) Base64 character set, ordered by index 0–63. */
    private static final String B64 =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // -------------------------------------------------------------------------
    // Base4096 codec state (lazily initialised from config)
    // -------------------------------------------------------------------------

    /**
     * Encode table: index → Unicode character. Each entry maps a pair of Base64
     * characters (indices a, b) to the single character {@code encodeMap[a*64+b]}.
     * {@code null} until {@link #initMapsIfNeeded()} is called.
     */
    private static char[] encodeMap = null;

    /**
     * Decode table: Unicode character → index. Inverse of {@link #encodeMap}.
     * {@code null} until {@link #initMapsIfNeeded()} is called.
     */
    private static Map<Character, Integer> decodeMap = null;

    // -------------------------------------------------------------------------
    // Replay-attack prevention: bounded LRU set of seen ciphertexts
    // -------------------------------------------------------------------------

    /**
     * Thread-safe set of ciphertext strings seen since startup. Capped at 10 000
     * entries; oldest entries are evicted first.
     */
    private static final java.util.Set<String> seenCiphertexts =
            java.util.Collections.synchronizedSet(
                java.util.Collections.newSetFromMap(
                    new java.util.LinkedHashMap<>() {
                        @Override
                        protected boolean removeEldestEntry(java.util.Map.Entry<String, Boolean> eldest) {
                            return size() > 10_000;
                        }
                    }
                )
            );

    /** Non-instantiable utility class. */
    private SecureChatUpdatedCryptoUtil() {}

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Returns the current SCU message prefix from config.
     *
     * <p>The prefix is prepended to every encrypted message so recipients can
     * identify SCU payloads without attempting decryption on every chat message.
     * Falls back to {@code "试中"} if the config value is absent or blank.</p>
     *
     * @return the prefix string, never {@code null}
     */
    public static String getPrefix() {
        String p = SecureChatUpdatedConfig.getPrefix();
        return (p != null && !p.isBlank()) ? p : "试中";
    }

    /**
     * Invalidates the cached Base4096 encode/decode maps so they are rebuilt
     * from the current config on the next encrypt/decrypt call.
     *
     * <p>Must be called after the user changes the alphabet in
     * {@link KeyConfigScreen}.</p>
     */
    public static void resetMaps() {
        encodeMap = null;
        decodeMap = null;
    }

    /**
     * Encrypts {@code plaintext} with the given {@code passphrase}.
     *
     * <p>A fresh random salt and IV are generated for every call, so two
     * encryptions of the same plaintext always produce different ciphertexts.</p>
     *
     * @param plaintext  the message to encrypt
     * @param passphrase the encryption key (from config)
     * @return the encoded ciphertext string (Base4096 or Base64 depending on config)
     * @throws Exception if key derivation or encryption fails
     */
    public static String encrypt(String plaintext, char[] passphrase) throws Exception {
        byte[] salt = new byte[SALT_LEN];
        byte[] iv   = new byte[IV_LEN];
        new SecureRandom().nextBytes(salt);
        new SecureRandom().nextBytes(iv);

        // Embed timestamp so the receiver can detect stale/replayed messages
        String timestamped = System.currentTimeMillis() + SEPARATOR + plaintext;

        SecretKey key    = deriveKey(passphrase, salt);
        Cipher    cipher = Cipher.getInstance(ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LEN, iv));
        byte[] ciphertext = cipher.doFinal(timestamped.getBytes(StandardCharsets.UTF_8));

        // Pack: [salt | IV | ciphertext+GCM-tag]
        byte[] payload = new byte[SALT_LEN + IV_LEN + ciphertext.length];
        System.arraycopy(salt,       0, payload, 0,                 SALT_LEN);
        System.arraycopy(iv,         0, payload, SALT_LEN,          IV_LEN);
        System.arraycopy(ciphertext, 0, payload, SALT_LEN + IV_LEN, ciphertext.length);

        String b64 = Base64.getEncoder().encodeToString(payload);
        return SecureChatUpdatedConfig.isUseBase4096() ? compress(b64) : b64;
    }

    /**
     * Possible outcomes of a decryption attempt.
     */
    public enum DecryptError {
        /** Decryption succeeded. */
        OK,
        /** Ciphertext does not match the current key (or is corrupt). */
        WRONG_KEY,
        /** This exact ciphertext has been received before (replay attack). */
        REPLAY,
        /** Message timestamp is outside the allowed clock-skew window. */
        EXPIRED;

        /** @return {@code true} iff this error represents success */
        public boolean isOk() { return this == OK; }
    }

    /**
     * Pairs a {@link DecryptError} with the recovered plaintext (only meaningful
     * when {@code error == OK}).
     */
    public record DecryptResult(DecryptError error, String plaintext) {
        /** Convenience factory for a successful result. */
        public static DecryptResult ok(String plaintext)    { return new DecryptResult(DecryptError.OK, plaintext); }
        /** Convenience factory for a failed result. */
        public static DecryptResult err(DecryptError error) { return new DecryptResult(error, null); }
    }

    /**
     * Attempts to decrypt a raw SCU payload (the part of the chat message after
     * the prefix).
     *
     * <p>Steps:
     * <ol>
     *   <li>Reject if this ciphertext has already been seen (replay attack).</li>
     *   <li>Decode from Base4096 (if enabled) or plain Base64.</li>
     *   <li>Split out salt, IV, and ciphertext from the packed binary.</li>
     *   <li>Derive the AES key and decrypt.</li>
     *   <li>Parse the {@code "<timestamp>|<plaintext>"} format; reject if the
     *       timestamp is outside the clock-skew window.</li>
     * </ol>
     *
     * @param payload    ciphertext string (without prefix)
     * @param passphrase the decryption key (from config)
     * @return a {@link DecryptResult} containing either the plaintext or an
     *         error code
     */
    public static DecryptResult decrypt(String payload, char[] passphrase) {
        try {
            // Replay check — add returns false if the element was already present
            if (!seenCiphertexts.add(payload))
                return DecryptResult.err(DecryptError.REPLAY);

            // Decode: try Base4096 first, fall back to raw Base64
            String b64 = null;
            if (SecureChatUpdatedConfig.isUseBase4096()) {
                b64 = decompress(payload);
            }
            if (b64 == null) {
                // Base4096 disabled, or decompress returned null (unknown character)
                b64 = payload;
            }

            byte[] raw = Base64.getDecoder().decode(b64);
            if (raw.length < SALT_LEN + IV_LEN + 1)
                return DecryptResult.err(DecryptError.WRONG_KEY);

            // Unpack binary payload
            byte[] salt       = Arrays.copyOfRange(raw, 0,                 SALT_LEN);
            byte[] iv         = Arrays.copyOfRange(raw, SALT_LEN,          SALT_LEN + IV_LEN);
            byte[] ciphertext = Arrays.copyOfRange(raw, SALT_LEN + IV_LEN, raw.length);

            // Decrypt — GCM will throw if the auth tag does not verify
            SecretKey key    = deriveKey(passphrase, salt);
            Cipher    cipher = Cipher.getInstance(ALGO);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LEN, iv));
            String decrypted = new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);

            // Parse embedded timestamp
            int sep = decrypted.indexOf(SEPARATOR);
            if (sep < 0) return DecryptResult.err(DecryptError.WRONG_KEY);

            long msgTime;
            try {
                msgTime = Long.parseLong(decrypted.substring(0, sep));
            } catch (NumberFormatException e) {
                return DecryptResult.err(DecryptError.WRONG_KEY);
            }

            // Reject messages outside the allowed clock-skew window
            if (Math.abs(System.currentTimeMillis() - msgTime) > CLOCK_SKEW_MS)
                return DecryptResult.err(DecryptError.EXPIRED);

            return DecryptResult.ok(decrypted.substring(sep + SEPARATOR.length()));

        } catch (Exception e) {
            // Any crypto exception (bad tag, bad padding, etc.) means wrong key or corruption
            return DecryptResult.err(DecryptError.WRONG_KEY);
        }
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /**
     * Lazily initialises {@link #encodeMap} and {@link #decodeMap} from the
     * alphabet stored in config.
     *
     * <p>Does nothing if the maps are already populated. Throws
     * {@link IllegalStateException} if the alphabet is not exactly 4096
     * characters.</p>
     */
    private static void initMapsIfNeeded() {
        if (encodeMap != null) return;

        String alpha = SecureChatUpdatedConfig.getAlphabet();
        if (alpha == null || alpha.isBlank()) return;

        if (alpha.length() != 4096)
            throw new IllegalStateException(
                    "ALPHABET must be exactly 4096 characters, got " + alpha.length());

        encodeMap = alpha.toCharArray();
        decodeMap = new HashMap<>(4096);
        for (int i = 0; i < 4096; i++) {
            decodeMap.put(encodeMap[i], i);
        }
    }

    /**
     * Compresses a Base64 string to a shorter form using the Base4096 alphabet.
     *
     * <p>Each pair of Base64 characters (6+6 = 12 bits) is mapped to a single
     * Unicode code point from the 4096-entry alphabet (12 bits), roughly halving
     * the character count. Padding ({@code '='}) is stripped first and handled
     * specially for odd-length inputs.</p>
     *
     * <p>Returns the original string unchanged if the alphabet is not loaded.</p>
     *
     * @param b64 Base64-encoded string (with or without padding)
     * @return compressed string, or {@code b64} if the alphabet is unavailable
     */
    private static String compress(String b64) {
        initMapsIfNeeded();
        if (encodeMap == null) return b64;

        // Strip padding before processing; handled explicitly for odd tails
        String stripped = b64.replace("=", "");
        StringBuilder sb = new StringBuilder(stripped.length() / 2 + 2);

        int i = 0;
        while (i < stripped.length() - 1) {
            int a = B64.indexOf(stripped.charAt(i));
            int b = B64.indexOf(stripped.charAt(i + 1));
            sb.append(encodeMap[a * 64 + b]);
            i += 2;
        }

        // Odd trailing character: emit a literal '=' sentinel followed by the char
        if (i < stripped.length()) {
            sb.append('=');
            sb.append(stripped.charAt(i));
        }

        return sb.toString();
    }

    /**
     * Decompresses a Base4096-encoded string back to standard Base64.
     *
     * <p>Inverse of {@link #compress}. Each Base4096 character maps back to two
     * Base64 characters; the {@code '='} sentinel restores an odd trailing
     * character. Re-adds Base64 padding so the result length is a multiple of 4.</p>
     *
     * <p>Returns {@code null} if a character is not found in the decode map
     * (indicates the payload was not Base4096-encoded).</p>
     *
     * @param compressed Base4096-encoded string
     * @return decoded Base64 string with padding, or {@code null} on map miss
     */
    private static String decompress(String compressed) {
        initMapsIfNeeded();
        if (encodeMap == null) return compressed;

        StringBuilder sb = new StringBuilder(compressed.length() * 2);
        int i = 0;

        while (i < compressed.length()) {
            char c = compressed.charAt(i);
            if (c == '=') {
                // Sentinel: next character is a raw Base64 char (odd-length tail)
                if (i + 1 < compressed.length()) sb.append(compressed.charAt(i + 1));
                i += 2;
            } else {
                Integer idx = decodeMap.get(c);
                if (idx == null) return null; // unknown character — not Base4096
                sb.append(B64.charAt(idx / 64));
                sb.append(B64.charAt(idx % 64));
                i++;
            }
        }

        // Restore Base64 padding to make length a multiple of 4
        while (sb.length() % 4 != 0) sb.append('=');
        return sb.toString();
    }

    /**
     * Derives a 256-bit AES key from {@code passphrase} and {@code salt} using
     * PBKDF2-HMAC-SHA256.
     *
     * @param passphrase the user-supplied passphrase
     * @param salt       random salt bytes (at least {@value #SALT_LEN} bytes)
     * @return a {@link SecretKey} suitable for AES-GCM
     * @throws Exception if the JCA provider does not support the KDF
     */
    private static SecretKey deriveKey(char[] passphrase, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF);
        KeySpec spec = new PBEKeySpec(passphrase, salt, ITERATIONS, KEY_BITS);
        byte[] raw   = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(raw, "AES");
    }
}

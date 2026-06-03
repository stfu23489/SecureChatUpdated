package dev.securechatupdated;

import net.fabricmc.loader.api.FabricLoader;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

/**
 * Persistent configuration for Secure Chat Updated.
 *
 * <p>Config is stored as a {@code .properties} file at
 * {@code <config dir>/securechatupdated.properties}. If the file does not
 * exist on first load, it is seeded from the bundled resource
 * {@code /securechatupdated_default.properties}.</p>
 *
 * <p>All setters persist immediately via {@link #save()}. This class is a
 * non-instantiable utility; all members are static.</p>
 *
 * <p><strong>Security note:</strong> the passphrase is stored as a
 * {@code char[]} rather than a {@link String} so it can be zeroed from
 * memory when no longer needed (though this mod does not currently do so).
 * The config file itself is plaintext — keep it private.</p>
 */
public final class SecureChatUpdatedConfig {

    /** Path to the active config file inside Fabric's config directory. */
    private static final Path CONFIG_FILE =
            FabricLoader.getInstance().getConfigDir().resolve("securechatupdated.properties");

    // --- In-memory config values ---

    /** Custom Base4096 encoding alphabet (must be exactly 4096 unique chars). */
    private static String  alphabet    = null;

    /** Encryption passphrase as a char array (avoids String interning). */
    private static char[]  passphrase  = null;

    /** Whether SCU encryption is currently active. */
    private static boolean enabled     = true;

    /** Message prefix that identifies an SCU-encrypted payload in chat. */
    private static String  prefix      = null;

    /** Whether to compress ciphertext using the Base4096 alphabet. */
    private static boolean useBase4096 = true;

    // --- Getters ---

    /** @return the custom Base4096 alphabet, or {@code null} if not set */
    public static String  getAlphabet()    { return alphabet;    }

    /** @return the current passphrase as a char array, or {@code null} if unset */
    public static char[]  getPassphrase()  { return passphrase;  }

    /** @return {@code true} if SCU encryption is enabled */
    public static boolean isEnabled()      { return enabled;     }

    /** @return the SCU message prefix string, or {@code null} if unset */
    public static String  getPrefix()      { return prefix;      }

    /** @return {@code true} if Base4096 compression is enabled */
    public static boolean isUseBase4096()  { return useBase4096; }

    // --- Setters (all persist immediately) ---

    /** Sets the Base4096 alphabet and saves. */
    public static void setAlphabet(String value)     { alphabet    = value;              save(); }

    /** Sets the enabled flag (does not persist — runtime toggle only). */
    public static void setEnabled(boolean value)     { enabled     = value;                     }

    /** Converts {@code raw} to a char array, stores as the passphrase, and saves. */
    public static void setPassphrase(String raw)     { passphrase  = raw.toCharArray();   save(); }

    /** Sets the message prefix and saves. */
    public static void setPrefix(String value)       { prefix      = value;              save(); }

    /** Sets the Base4096 toggle and saves. */
    public static void setUseBase4096(boolean value) { useBase4096 = value;              save(); }

    /** Non-instantiable utility class. */
    private SecureChatUpdatedConfig() {}

    // -------------------------------------------------------------------------
    // Loading and saving
    // -------------------------------------------------------------------------

    /**
     * Reads a single property value from the bundled default config resource.
     *
     * <p>Used as a fallback when a key is absent or blank in the user's config
     * file, ensuring sensible defaults even on first run.</p>
     *
     * @param key the property key to look up
     * @return the default value, or {@code null} if the resource is missing or
     *         the key is not found
     */
    private static String loadDefaultProperty(String key) {
        try (InputStream in = SecureChatUpdatedConfig.class
                    .getResourceAsStream("/securechatupdated_default.properties");
             InputStreamReader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
            if (in == null) return null;
            Properties defaults = new Properties();
            defaults.load(reader);
            return defaults.getProperty(key);
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * Loads configuration from {@link #CONFIG_FILE}.
     *
     * <p>If the file does not yet exist, {@link #copyDefaultConfig()} seeds it
     * from the bundled resource. For each key, if the stored value is absent or
     * blank the corresponding default is loaded and the file is re-saved so
     * subsequent runs have all keys present.</p>
     */
    public static void load() {
        if (!Files.exists(CONFIG_FILE)) {
            copyDefaultConfig();
            return;
        }

        Properties props = new Properties();
        try (InputStream in   = Files.newInputStream(CONFIG_FILE);
             InputStreamReader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
            props.load(reader);

            // passphrase
            String p = props.getProperty("passphrase");
            if (p != null && !p.isBlank()) {
                passphrase = p.toCharArray();
            } else {
                String defaultPass = loadDefaultProperty("passphrase");
                if (defaultPass != null) passphrase = defaultPass.toCharArray();
                save();
            }

            // enabled
            String e = props.getProperty("enabled");
            if (e != null) enabled = Boolean.parseBoolean(e);

            // alphabet
            String a = props.getProperty("alphabet");
            if (a != null && !a.isBlank()) {
                alphabet = a;
            } else {
                alphabet = loadDefaultProperty("alphabet");
                save();
            }

            // prefix
            String pfx = props.getProperty("prefix");
            if (pfx != null && !pfx.isBlank()) {
                prefix = pfx;
            } else {
                String defaultPfx = loadDefaultProperty("prefix");
                if (defaultPfx != null && !defaultPfx.isBlank()) prefix = defaultPfx;
                save();
            }

            // use_base4096
            String b4096 = props.getProperty("use_base4096");
            if (b4096 != null) {
                useBase4096 = Boolean.parseBoolean(b4096);
            } else {
                String defaultB4096 = loadDefaultProperty("use_base4096");
                if (defaultB4096 != null) useBase4096 = Boolean.parseBoolean(defaultB4096);
                save();
            }

        } catch (IOException ignored) {}
    }

    /**
     * Writes all current config values to {@link #CONFIG_FILE}.
     *
     * <p>Null or blank values are omitted so the file stays clean. Called
     * automatically by all setters and during load when defaults are applied.</p>
     */
    private static void save() {
        Properties props = new Properties();

        if (passphrase != null)
            props.setProperty("passphrase", new String(passphrase));
        props.setProperty("enabled", String.valueOf(enabled));
        if (alphabet != null && !alphabet.isBlank())
            props.setProperty("alphabet", alphabet);
        if (prefix != null && !prefix.isBlank())
            props.setProperty("prefix", prefix);
        props.setProperty("use_base4096", String.valueOf(useBase4096));

        try (OutputStream out        = Files.newOutputStream(CONFIG_FILE);
             OutputStreamWriter writer = new OutputStreamWriter(out, StandardCharsets.UTF_8)) {
            props.store(writer, "Secure Chat Updated config, keep this file private!");
        } catch (IOException ignored) {}
    }

    /**
     * Seeds {@link #CONFIG_FILE} by copying the bundled default resource.
     *
     * <p>Creates any missing parent directories. Falls back to {@link #save()}
     * (which writes only current in-memory values) if the resource is absent.</p>
     */
    private static void copyDefaultConfig() {
        try (InputStream in = SecureChatUpdatedConfig.class
                    .getResourceAsStream("/securechatupdated_default.properties")) {
            if (in == null) { save(); return; }
            Files.createDirectories(CONFIG_FILE.getParent());
            Files.copy(in, CONFIG_FILE);
        } catch (IOException e) {
            save();
        }
    }
}

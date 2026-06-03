package dev.securechatupdated;

import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.fabric.api.client.message.v1.ClientReceiveMessageEvents;
import net.fabricmc.fabric.api.client.message.v1.ClientSendMessageEvents;
import net.minecraft.client.Minecraft;
import net.minecraft.network.chat.Component;
import net.minecraft.network.chat.MutableComponent;
import net.minecraft.network.chat.contents.PlainTextContents;
import net.minecraft.network.chat.contents.TranslatableContents;
import java.util.ArrayList;
import java.util.List;
import net.minecraft.network.chat.HoverEvent;

/**
 * Client-side entry point for Secure Chat Updated (SCU).
 *
 * <p>Registers three Fabric message event hooks on startup:
 * <ol>
 *   <li>{@code ALLOW_CHAT} (send) — encrypts outgoing messages when enabled.</li>
 *   <li>{@code ALLOW_CHAT} (receive) — re-routes incoming chat through the
 *       system-message channel so SCU can control rendering.</li>
 *   <li>{@code MODIFY_GAME} (receive) — decrypts SCU-prefixed content in
 *       incoming game messages and colours/labels results; also detects spoofs.</li>
 * </ol>
 */
public class SecureChatUpdatedClient implements ClientModInitializer {

    @Override
    public void onInitializeClient() {
        SecureChatUpdatedConfig.load();

        // --- Outgoing: encrypt before sending ---
        ClientSendMessageEvents.ALLOW_CHAT.register(message -> {
            if (shouldEncrypt(message)) {
                String encrypted = encryptMessage(message);
                if (encrypted != null) {
                    // Send the encrypted string directly and suppress the original
                    Minecraft.getInstance().player.connection.sendChat(encrypted);
                }
                // Return false to cancel the original un-encrypted send
                return false;
            }
            return true;
        });

        // --- Incoming chat: redirect to system-message slot ---
        // Chat messages go through MODIFY_GAME below for decryption; routing
        // them via sendSystemMessage ensures they always pass through that hook.
        ClientReceiveMessageEvents.ALLOW_CHAT.register((message, signedMessage, sender, params, receptionTimestamp) -> {
            Minecraft mc = Minecraft.getInstance();
            mc.player.sendSystemMessage(message);
            return false; // suppress the original chat rendering
        });

        // --- Incoming game: decrypt SCU payload and flag spoofs ---
        ClientReceiveMessageEvents.MODIFY_GAME.register((message, overlay) -> {
            String raw = message.getString();
            Component result = transformComponent(message);

            if (result != message) {
                // Message contained an SCU payload — prefix it with a green label
                return Component.empty()
                        .append(Component.literal("[Secure Chat] ").withStyle(s -> s.withColor(0x55FF55)))
                        .append(result);
            }

            // Detect a message that looks like an SCU label but was not encrypted
            // (i.e. someone manually typed "[Secure Chat] ..." to impersonate SCU)
            if (raw.startsWith("[Secure Chat] ")) {
                return Component.literal("[Secure Chat Spoof Detected!] ")
                        .withStyle(s -> s.withColor(0xFF0000))
                        .append(message);
            }

            return message;
        });
    }

    /**
     * Returns {@code true} if the given outgoing message should be encrypted.
     *
     * <p>Encryption is skipped when SCU is disabled or when the message already
     * carries the SCU prefix (meaning it has been encrypted upstream, e.g. by
     * {@link dev.securechatupdated.mixin.SendChatMixin}).</p>
     *
     * @param message the raw outgoing chat string
     * @return {@code true} if the message should be encrypted before sending
     */
    public static boolean shouldEncrypt(String message) {
        return SecureChatUpdatedConfig.isEnabled()
                && !message.startsWith(SecureChatUpdatedCryptoUtil.getPrefix());
    }

    /**
     * Encrypts {@code message} and prepends the SCU prefix.
     *
     * <p>Returns {@code null} and shows a notice to the player if encryption
     * fails or if the resulting string would exceed Minecraft's 256-character
     * chat limit.</p>
     *
     * @param message plaintext message to encrypt
     * @return the prefixed ciphertext string, or {@code null} on failure
     */
    public static String encryptMessage(String message) {
        try {
            String encrypted = SecureChatUpdatedCryptoUtil.getPrefix()
                    + SecureChatUpdatedCryptoUtil.encrypt(message, SecureChatUpdatedConfig.getPassphrase());
            if (encrypted.length() > 256) {
                notice("Message too long after encryption (" + encrypted.length() + "/256 chars)");
                return null;
            }
            return encrypted;
        } catch (Exception e) {
            e.printStackTrace();
            notice("Encrypt failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Recursively walks the {@link Component} tree looking for nodes that
     * contain the SCU prefix, and replaces them with decrypted (or error)
     * nodes.
     *
     * <p>Handles three component content types:
     * <ul>
     *   <li>{@link PlainTextContents.LiteralContents} — scans the raw text
     *       string for the prefix.</li>
     *   <li>{@link TranslatableContents} — scans each argument (both
     *       {@link Component} and {@link String} args).</li>
     *   <li>Everything else — recurses into sibling components.</li>
     * </ul>
     *
     * @param root the component (or subtree) to scan
     * @return a modified copy of {@code root} if any decryption occurred,
     *         or {@code root} itself (by reference equality) if nothing changed
     */
    private static Component transformComponent(Component root) {
        // --- Literal text node ---
        if (root.getContents() instanceof PlainTextContents.LiteralContents lc) {
            String content = lc.text();
            int idx = content.indexOf(SecureChatUpdatedCryptoUtil.getPrefix());
            if (idx >= 0) {
                return decryptNode(content, idx, root.getStyle());
            }
            return root;
        }

        // --- Translatable node (e.g. "<player> <message>" chat format) ---
        if (root.getContents() instanceof TranslatableContents tc) {
            boolean changed = false;
            Object[] oldArgs = tc.getArgs();
            Object[] newArgs = new Object[oldArgs.length];

            for (int i = 0; i < oldArgs.length; i++) {
                if (oldArgs[i] instanceof Component argComponent) {
                    // Recurse into Component arguments
                    Component transformed = transformComponent(argComponent);
                    newArgs[i] = transformed;
                    if (transformed != argComponent) changed = true;
                } else if (oldArgs[i] instanceof String argString) {
                    // Check plain-String arguments for the prefix
                    int idx = argString.indexOf(SecureChatUpdatedCryptoUtil.getPrefix());
                    if (idx >= 0) {
                        newArgs[i] = decryptNode(argString, idx, root.getStyle());
                        changed = true;
                    } else {
                        newArgs[i] = oldArgs[i];
                    }
                } else {
                    newArgs[i] = oldArgs[i];
                }
            }

            if (changed) {
                MutableComponent rebuilt = MutableComponent.create(
                    new TranslatableContents(tc.getKey(), tc.getFallback(), newArgs)
                ).withStyle(root.getStyle());
                for (Component s : root.getSiblings()) rebuilt.append(s);
                return rebuilt;
            }
        }

        // --- Fallback: recurse into sibling list ---
        List<Component> siblings = root.getSiblings();
        if (siblings.isEmpty()) return root;

        boolean changed = false;
        List<Component> newSiblings = new ArrayList<>(siblings.size());
        for (Component sibling : siblings) {
            Component transformed = transformComponent(sibling);
            newSiblings.add(transformed);
            if (transformed != sibling) changed = true;
        }

        if (!changed) return root;

        MutableComponent rebuilt = MutableComponent.create(root.getContents()).withStyle(root.getStyle());
        for (Component s : newSiblings) rebuilt.append(s);
        return rebuilt;
    }

    /**
     * Decrypts the SCU payload found in {@code content} starting at
     * {@code idx} and returns a {@link Component} that shows the result.
     *
     * <p>Any text before the SCU prefix is preserved verbatim. The decrypted
     * (or error) text is coloured and given a hover tooltip showing the raw
     * ciphertext for inspection.</p>
     *
     * <p>Possible outcomes:
     * <ul>
     *   <li>{@code OK} — green plaintext with ciphertext hover.</li>
     *   <li>{@code REPLAY} — orange warning (duplicate ciphertext seen before).</li>
     *   <li>{@code EXPIRED} — yellow warning (timestamp outside allowed clock skew).</li>
     *   <li>{@code WRONG_KEY} — red warning (decryption failed; wrong key or corrupt).</li>
     * </ul>
     *
     * @param content full text string containing the prefix
     * @param idx     index of the prefix within {@code content}
     * @param style   base text style inherited from the parent component
     * @return a {@link Component} with the decrypted (or error) content
     */
    private static Component decryptNode(String content, int idx, net.minecraft.network.chat.Style style) {
        String payload = content.substring(idx + SecureChatUpdatedCryptoUtil.getPrefix().length());
        String prefix  = content.substring(0, idx);

        MutableComponent result = Component.literal(prefix).withStyle(style);

        // Hover tooltip shows the raw ciphertext so the user can verify or copy it
        Component hoverText = Component.literal("Ciphertext:\n")
                .append(Component.literal(SecureChatUpdatedCryptoUtil.getPrefix() + payload)
                        .withStyle(s -> s.withColor(0xAAAAAA)));

        SecureChatUpdatedCryptoUtil.DecryptResult dr =
                SecureChatUpdatedCryptoUtil.decrypt(payload, SecureChatUpdatedConfig.getPassphrase());

        switch (dr.error()) {
            case OK ->
                result.append(Component.literal(dr.plaintext()).withStyle(s -> s
                        .withColor(0x55FF55)
                        .withHoverEvent(new HoverEvent.ShowText(hoverText))));
            case REPLAY ->
                result.append(Component.literal("[SCU: Blocked Replay Attack!]").withStyle(s -> s
                        .withColor(0xFF5500)
                        .withHoverEvent(new HoverEvent.ShowText(hoverText))));
            case EXPIRED ->
                result.append(Component.literal("[SCU: Blocked Expired Text!]").withStyle(s -> s
                        .withColor(0xFFAA00)
                        .withHoverEvent(new HoverEvent.ShowText(hoverText))));
            case WRONG_KEY ->
                result.append(Component.literal("[SCU: Wrong Key]").withStyle(s -> s
                        .withColor(0xFF5555)
                        .withHoverEvent(new HoverEvent.ShowText(hoverText))));
        }

        return result;
    }

    /**
     * Sends a system message to the local player prefixed with
     * {@code [Secure Chat Updated]}.
     *
     * <p>Safe to call at any time; silently does nothing if the player or
     * Minecraft instance is not yet available.</p>
     *
     * @param msg the message text to display
     */
    public static void notice(String msg) {
        Minecraft mc = Minecraft.getInstance();
        if (mc != null && mc.player != null) {
            mc.player.sendSystemMessage(Component.literal("[Secure Chat Updated] " + msg));
        }
    }
}

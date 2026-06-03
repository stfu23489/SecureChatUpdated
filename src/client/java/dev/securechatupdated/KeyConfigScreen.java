package dev.securechatupdated;

import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.EditBox;
import net.minecraft.client.gui.components.StringWidget;
import net.minecraft.client.gui.screens.ChatScreen;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.chat.Component;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;

/**
 * In-game configuration screen for Secure Chat Updated.
 *
 * <p>Opened by Ctrl+clicking the [SCU] button in the chat bar
 * (see {@link dev.securechatupdated.mixin.ChatScreenMixin}).</p>
 *
 * <h2>Basic controls (always visible)</h2>
 * <ul>
 *   <li><b>Key field</b> — enter any passphrase; shared by all players who want
 *       to read the encrypted messages.</li>
 *   <li><b>Save</b> — persist the key (and advanced settings if visible) and
 *       return to chat.</li>
 *   <li><b>Cancel</b> — discard unsaved changes and return to chat.</li>
 *   <li><b>Generate Key</b> — fill the key field with 32 cryptographically
 *       random bytes encoded as Base64.</li>
 *   <li><b>Base4096</b> toggle — enable/disable Base4096 compression of
 *       ciphertexts (makes messages shorter in chat).</li>
 *   <li><b>Advanced</b> — show/hide the advanced section.</li>
 * </ul>
 *
 * <h2>Advanced controls (hidden by default)</h2>
 * <ul>
 *   <li><b>Prefix</b> — the string that identifies SCU-encrypted messages;
 *       must be the same for all participants.</li>
 *   <li><b>Alphabet</b> — custom 4096-character encoding alphabet for
 *       Base4096 compression.</li>
 * </ul>
 */
public class KeyConfigScreen extends Screen {

    /** The chat screen to return to when this screen closes. */
    private final ChatScreen returnScreen;

    // Basic widgets
    private EditBox passphraseField;

    // Advanced widgets
    private EditBox      prefixField;
    private EditBox      alphabetField;
    private StringWidget prefixLabel;
    private StringWidget alphabetLabel;
    private StringWidget advancedTitle;

    /** Whether the advanced section is currently visible. */
    private boolean advancedVisible = false;

    /**
     * @param returnScreen the chat screen to navigate back to on save/cancel
     */
    public KeyConfigScreen(ChatScreen returnScreen) {
        super(Component.literal("SCU Configuration"));
        this.returnScreen = returnScreen;
    }

    // -------------------------------------------------------------------------
    // Screen lifecycle
    // -------------------------------------------------------------------------

    @Override
    protected void init() {
        int cx = this.width  / 2;
        int cy = this.height / 2;

        // --- Title ---
        this.addRenderableWidget(new StringWidget(
            cx - this.font.width("SCU Configuration") / 2, cy - 60, 320, 14,
            Component.literal("SCU Configuration").withStyle(s -> s.withColor(0x55FF55)),
            this.font));

        // --- Key (passphrase) row ---
        int labelW = this.font.width("Key: ");
        int fieldW = 300;
        int rowX   = cx - (labelW + fieldW) / 2;

        this.addRenderableWidget(new StringWidget(
            rowX, cy - 36, labelW, 12,
            Component.literal("Key:").withStyle(s -> s.withColor(0xAAAAAA)),
            this.font));

        passphraseField = new EditBox(this.font, rowX + labelW, cy - 42, fieldW, 20,
            Component.literal("passphrase"));
        passphraseField.setMaxLength(256);
        passphraseField.setValue(new String(SecureChatUpdatedConfig.getPassphrase()));
        passphraseField.setHint(
            Component.literal("Enter key...").withStyle(s -> s.withColor(0x666666)));
        this.addRenderableWidget(passphraseField);
        this.setInitialFocus(passphraseField);

        // --- Main button row ---
        // Use a local record to pair button labels with widths and actions
        record BtnDef(Component label, int width, Button.OnPress action) {}

        // Base4096 button label reflects current toggle state; captured as a
        // Supplier so the button can refresh its own label on click.
        java.util.function.Supplier<Component> base4096Label = () ->
            Component.literal("Base4096: " + (SecureChatUpdatedConfig.isUseBase4096() ? "ON" : "OFF"))
                .withStyle(s -> s.withColor(
                    SecureChatUpdatedConfig.isUseBase4096() ? 0x55FF55 : 0xAAAAAA));

        List<BtnDef> buttons = new java.util.ArrayList<>();
        buttons.add(new BtnDef(
            Component.literal("Save").withStyle(s -> s.withColor(0x55FF55)),
            50, btn -> saveAndReturn()));
        buttons.add(new BtnDef(
            Component.literal("Cancel"),
            50, btn -> this.minecraft.setScreen(returnScreen)));
        buttons.add(new BtnDef(
            Component.literal("Generate Key").withStyle(s -> s.withColor(0xAAAAAA)),
            85, btn -> {
                // Fill the passphrase field with 32 random bytes (256 bits) as Base64
                byte[] key = new byte[32];
                new SecureRandom().nextBytes(key);
                passphraseField.setValue(Base64.getEncoder().encodeToString(key));
            }));
        buttons.add(new BtnDef(base4096Label.get(), 85, btn -> {
            SecureChatUpdatedConfig.setUseBase4096(!SecureChatUpdatedConfig.isUseBase4096());
            btn.setMessage(base4096Label.get());
        }));
        buttons.add(new BtnDef(
            Component.literal("Advanced").withStyle(s -> s.withColor(0x888888)),
            70, btn -> toggleAdvanced()));

        // Lay out buttons in a centred horizontal row with a fixed gap
        int gap          = 4;
        int btnRowWidth  = buttons.stream().mapToInt(BtnDef::width).sum()
                         + gap * (buttons.size() - 1);
        int btnRowX      = cx - btnRowWidth / 2;
        int offsetX      = 0;
        for (BtnDef def : buttons) {
            this.addRenderableWidget(Button.builder(def.label(), def.action())
                .bounds(btnRowX + offsetX, cy - 16, def.width(), 20)
                .build());
            offsetX += def.width() + gap;
        }

        // --- Advanced section ---
        int advLabelW = this.font.width("Alphabet: ");
        int advFieldW = 300;
        int advRowX   = cx - (advLabelW + advFieldW) / 2;

        advancedTitle = new StringWidget(
            cx - this.font.width("Advanced Configuration") / 2, cy + 12, 320, 14,
            Component.literal("Advanced Configuration").withStyle(s -> s.withColor(0x888888)),
            this.font);

        prefixLabel = new StringWidget(
            advRowX, cy + 34, advLabelW, 12,
            Component.literal("Prefix:").withStyle(s -> s.withColor(0xAAAAAA)),
            this.font);

        prefixField = new EditBox(this.font, advRowX + advLabelW, cy + 28, advFieldW, 20,
            Component.literal("prefix"));
        prefixField.setMaxLength(32);
        prefixField.setValue(SecureChatUpdatedCryptoUtil.getPrefix());
        prefixField.setHint(
            Component.literal("Message prefix...").withStyle(s -> s.withColor(0x666666)));

        alphabetLabel = new StringWidget(
            advRowX, cy + 58, advLabelW, 12,
            Component.literal("Alphabet:").withStyle(s -> s.withColor(0xAAAAAA)),
            this.font);

        alphabetField = new EditBox(this.font, advRowX + advLabelW, cy + 52, advFieldW, 20,
            Component.literal("alphabet"));
        alphabetField.setMaxLength(4096);
        String currentAlphabet = SecureChatUpdatedConfig.getAlphabet();
        alphabetField.setValue(currentAlphabet != null ? currentAlphabet : "");
        alphabetField.setHint(
            Component.literal("4096-char encoding alphabet...").withStyle(s -> s.withColor(0x666666)));

        // Start hidden; revealed only when the Advanced button is clicked
        setAdvancedWidgetsVisible(false);
        this.addRenderableWidget(advancedTitle);
        this.addRenderableWidget(prefixLabel);
        this.addRenderableWidget(prefixField);
        this.addRenderableWidget(alphabetLabel);
        this.addRenderableWidget(alphabetField);
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /** Toggles visibility of the advanced configuration widgets. */
    private void toggleAdvanced() {
        advancedVisible = !advancedVisible;
        setAdvancedWidgetsVisible(advancedVisible);
    }

    /** Sets all advanced-section widgets to the given {@code visible} state. */
    private void setAdvancedWidgetsVisible(boolean visible) {
        advancedTitle.visible = visible;
        prefixLabel.visible   = visible;
        prefixField.visible   = visible;
        alphabetLabel.visible = visible;
        alphabetField.visible = visible;
    }

    /**
     * Validates and persists the form values, then returns to the chat screen.
     *
     * <p>Always saves the passphrase. If the advanced section is open, also
     * saves any non-blank prefix or alphabet values. Changing the alphabet
     * invalidates the Base4096 codec maps via
     * {@link SecureChatUpdatedCryptoUtil#resetMaps()}.</p>
     */
    private void saveAndReturn() {
        String raw = passphraseField.getValue().trim();
        if (raw.isEmpty()) {
            SecureChatUpdatedClient.notice("Warning: No key set!");
        }
        SecureChatUpdatedConfig.setPassphrase(raw);

        if (advancedVisible) {
            String newPrefix = prefixField.getValue().trim();
            if (!newPrefix.isEmpty()) {
                SecureChatUpdatedConfig.setPrefix(newPrefix);
            }
            String newAlphabet = alphabetField.getValue().trim();
            if (!newAlphabet.isEmpty()) {
                SecureChatUpdatedConfig.setAlphabet(newAlphabet);
                // Alphabet changed — invalidate cached encode/decode maps
                SecureChatUpdatedCryptoUtil.resetMaps();
            }
        }

        SecureChatUpdatedClient.notice("Config updated");
        this.minecraft.setScreen(returnScreen);
    }

    @Override
    public boolean isPauseScreen() { return false; }
}

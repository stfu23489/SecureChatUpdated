package dev.securechatupdated.mixin;

import dev.securechatupdated.SecureChatUpdatedConfig;
import dev.securechatupdated.KeyConfigScreen;
import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.EditBox;
import net.minecraft.client.gui.screens.ChatScreen;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.chat.Component;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;
import com.mojang.blaze3d.platform.InputConstants;
import org.lwjgl.glfw.GLFW;
import net.minecraft.client.gui.components.Tooltip;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;
import net.minecraft.client.input.MouseButtonEvent;

/**
 * Mixin into {@link ChatScreen} to inject SCU controls.
 *
 * <p>Adds a small [SCU] ON/OFF toggle button in the chat bar area. Clicking it
 * toggles encryption; Ctrl+clicking opens the {@link KeyConfigScreen}.</p>
 *
 * <p>Holding Shift temporarily disables encryption (so plaintext can be typed
 * while Shift is held), then restores the prior state on release.</p>
 */
@Mixin(ChatScreen.class)
public class ChatScreenMixin extends Screen {
    protected ChatScreenMixin(Component title) { super(title); }

    /** The toggle button rendered in the chat bar. */
    private Button toggleButton;

    /** Whether Shift was held on the previous render frame. */
    private boolean lastShiftState = false;

    /**
     * The encryption state that was active before Shift was first pressed.
     * Stored as a static so it survives across render frames; reset on release.
     */
    private static boolean preShiftState = false;

    /**
     * Injected into {@code extractRenderState} (called every frame) to track
     * Shift key state changes.
     *
     * <p>On Shift press: saves the current enabled state into {@code preShiftState}
     * and disables encryption, allowing the player to type a plaintext message.
     * On Shift release: restores the saved state.</p>
     */
    @Inject(method = "extractRenderState", at = @At("HEAD"))
    private void scu$checkShift(net.minecraft.client.gui.GuiGraphicsExtractor graphics, int mouseX, int mouseY, float partialTick, CallbackInfo ci) {
        boolean shiftNow = InputConstants.isKeyDown(
            Minecraft.getInstance().getWindow(), GLFW.GLFW_KEY_LEFT_SHIFT
        ) || InputConstants.isKeyDown(
            Minecraft.getInstance().getWindow(), GLFW.GLFW_KEY_RIGHT_SHIFT
        );

        if (shiftNow && !lastShiftState) {
            // Shift just pressed — save state and disable encryption
            preShiftState = SecureChatUpdatedConfig.isEnabled();
            SecureChatUpdatedConfig.setEnabled(!preShiftState);
        } else if (!shiftNow && lastShiftState) {
            // Shift just released — restore saved state
            SecureChatUpdatedConfig.setEnabled(preShiftState);
        }

        lastShiftState = shiftNow;

        // Keep toggle button label in sync with current enabled state
        if (toggleButton != null) toggleButton.setMessage(getToggleLabel());
    }

    /**
     * Injected at the tail of {@code init} to add the SCU toggle button to the
     * chat screen. The button is added as render-only (no click handling here;
     * clicks are handled in {@link #scu$handleClick}).
     */
    @Inject(method = "init", at = @At("TAIL"))
    private void scu$addButtons(CallbackInfo ci) {
        Component hoverText = Component.literal("Secure Chat Updated\n").withStyle(s -> s.withColor(0x55FF55))
                              .append(Component.literal("Ctrl + Left Click").withStyle(s -> s.withColor(0x55FF55)))
                              .append(Component.literal(" to configure\n").withStyle(s -> s.withColor(0xAAAAAA)))
                              .append(Component.literal("Left Click").withStyle(s -> s.withColor(0x55FF55)))
                              .append(Component.literal(" to toggle encryption").withStyle(s -> s.withColor(0xAAAAAA)));

        toggleButton = Button.builder(
            getToggleLabel(),
            btn -> {}   // click is handled by scu$handleClick below
        ).bounds((this.width - 60) / 2, this.height - 32, 60, 14)
         .tooltip(Tooltip.create(hoverText))
         .build();

        this.addRenderableOnly(toggleButton);
    }

    /**
     * Injected at the head of {@code mouseClicked} to intercept clicks on the
     * SCU toggle button before vanilla processes them.
     *
     * <ul>
     *   <li>Plain left-click: toggles encryption on/off and refocuses the chat
     *       input so the player can keep typing without an extra click.</li>
     *   <li>Ctrl + left-click: opens {@link KeyConfigScreen} for passphrase and
     *       advanced settings.</li>
     * </ul>
     *
     * <p>Cancels the event so vanilla does not also process the click.</p>
     */
    @Inject(method = "mouseClicked", at = @At("HEAD"), cancellable = true)
    private void scu$handleClick(MouseButtonEvent event, boolean bl, CallbackInfoReturnable<Boolean> cir) {
        if (event.button() == 0 && toggleButton != null && toggleButton.isMouseOver(event.x(), event.y())) {
            boolean ctrl = InputConstants.isKeyDown(
                Minecraft.getInstance().getWindow(), GLFW.GLFW_KEY_LEFT_CONTROL
            ) || InputConstants.isKeyDown(
                Minecraft.getInstance().getWindow(), GLFW.GLFW_KEY_RIGHT_CONTROL
            );

            if (ctrl) {
                // Ctrl+click — open configuration screen
                Minecraft.getInstance().setScreen(new KeyConfigScreen((ChatScreen)(Object)this));
            } else {
                // Plain click — toggle encryption and re-focus the text input
                SecureChatUpdatedConfig.setEnabled(!SecureChatUpdatedConfig.isEnabled());
                toggleButton.setMessage(getToggleLabel());
                Minecraft.getInstance().execute(() -> {
                    EditBox input = ((ChatScreenAccessor)(Object)this).scu$getInput();
                    this.setFocused(input);
                    input.setFocused(true);
                    input.moveCursorToEnd(false);
                });
            }

            cir.setReturnValue(true);
            cir.cancel();
        }
    }

    /**
     * Injected at the head of {@code removed} (called when the chat screen
     * closes) to handle the edge case where the screen is dismissed while Shift
     * is still held down.
     *
     * <p>Without this, closing the screen mid-hold would leave encryption
     * permanently disabled because the key-release branch never runs.</p>
     */
    @Inject(method = "removed", at = @At("HEAD"))
    private void scu$onRemoved(CallbackInfo ci) {
        if (lastShiftState) {
            // Screen closed while Shift was held — restore encryption state
            SecureChatUpdatedConfig.setEnabled(preShiftState);
            lastShiftState = false;
        }
    }

    /**
     * Returns the appropriate label component for the toggle button based on
     * whether encryption is currently enabled.
     */
    private static Component getToggleLabel() {
        return SecureChatUpdatedConfig.isEnabled()
            ? Component.literal("[SCU] ON").withStyle(s -> s.withColor(0x55FF55))
            : Component.literal("[SCU] OFF").withStyle(s -> s.withColor(0xAAAAAA));
    }
}

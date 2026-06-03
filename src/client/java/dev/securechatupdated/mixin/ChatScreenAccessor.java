package dev.securechatupdated.mixin;

import net.minecraft.client.gui.components.EditBox;
import net.minecraft.client.gui.screens.ChatScreen;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Accessor;

/**
 * Mixin accessor for {@link ChatScreen} that exposes the private {@code input}
 * field (the chat text box) to the rest of the SCU mod.
 *
 * <p>Used by {@link ChatScreenMixin} after toggling encryption so focus can be
 * returned to the chat input without requiring the player to click again.</p>
 */
@Mixin(ChatScreen.class)
public interface ChatScreenAccessor {
    /**
     * Returns the chat text input {@link EditBox}.
     *
     * @return the {@code input} field from {@link ChatScreen}
     */
    @Accessor("input")
    EditBox scu$getInput();
}

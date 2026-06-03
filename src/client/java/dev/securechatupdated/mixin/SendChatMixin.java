package dev.securechatupdated.mixin;

import dev.securechatupdated.SecureChatUpdatedClient;
import net.minecraft.network.protocol.game.ServerboundChatPacket;
import net.minecraft.client.multiplayer.ClientPacketListener;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.ModifyArg;

/**
 * Mixin into {@link ClientPacketListener} that intercepts outgoing chat packets
 * and encrypts their message argument when SCU encryption is enabled.
 *
 * <p>This is a secondary encryption path that covers messages sent via
 * {@link ClientPacketListener#sendChat(String)} directly (e.g. from command
 * blocks or other mods), complementing the {@code ALLOW_CHAT} event handler in
 * {@link SecureChatUpdatedClient} which covers messages sent through the normal
 * chat screen.</p>
 */
@Mixin(ClientPacketListener.class)
public class SendChatMixin {

    /**
     * Modifies the {@code message} argument passed to the
     * {@link ServerboundChatPacket} constructor inside
     * {@code sendChat(String)}.
     *
     * <p>If the message should be encrypted (encryption enabled and message does
     * not already carry the SCU prefix), it is encrypted before being packed
     * into the outgoing packet. If encryption fails, the original plaintext is
     * sent so the player's message is not silently dropped.</p>
     *
     * @param message the outgoing chat message string
     * @return the encrypted message, or the original message if encryption is
     *         disabled, already encrypted, or fails
     */
    @ModifyArg(
        method = "sendChat(Ljava/lang/String;)V",
        at = @At(
            value = "INVOKE",
            target = "Lnet/minecraft/network/protocol/game/ServerboundChatPacket;<init>(Ljava/lang/String;Ljava/time/Instant;JLnet/minecraft/network/chat/MessageSignature;Lnet/minecraft/network/chat/LastSeenMessages$Update;)V"
        ),
        index = 0
    )
    private String encryptChatMessage(String message) {
        if (!SecureChatUpdatedClient.shouldEncrypt(message)) return message;
        String encrypted = SecureChatUpdatedClient.encryptMessage(message);
        // Fall back to plaintext if encryption returns null (e.g. message too long)
        return encrypted != null ? encrypted : message;
    }
}

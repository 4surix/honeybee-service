// Kotlin 1.9
// Gradle 8.5
// ---------------------------------------------------------------------------
package fr.asurix.honeybee


import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.CCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter

import java.nio.ByteBuffer
import java.nio.ByteOrder


/**
 * Gestionnaire du chiffrement et de la signature.
 */
object HoneybeeCrypto {
    private const val TAG = "HoneybeeCrypto"

    private const val PAYLOAD_MAX_SIZE = 13 // Taille maximum du Payload
    private const val MIC_SIZE = 6          // Taille du MIC (AES-CCM)
    private const val IV_SIZE = 10          // Taille de l'IV (List: 2 + Sender: 2 + Channel: 2 + Random: 4)
    private const val AES_KEY_SIZE = 16     // Taille de la clé AES-128 (16 bytes)

    /**
     * Chiffre un segment de données avec AES-CCM-128.
     * 
     * @param data Les données à chiffrer.
     * @param key La clé AES-128.
     * @param iv Le vecteur d'initialisation.
     * @return Une paire (données chiffrées, MIC).
     */
    fun encryptAesCcm(
        data: ByteArray, 
        key: ByteArray, 
        iv: ByteArray
    ): Pair<ByteArray, ByteArray>? {
        if (data.size > PAYLOAD_MAX_SIZE || key.size != AES_KEY_SIZE || iv.size != IV_SIZE) {
            return null
        }

        try {
            val cipher = CCMBlockCipher(AESEngine())
            val aeadParams = AEADParameters(KeyParameter(key), MIC_SIZE * 8, iv)
            cipher.init(true, aeadParams)

            val outputSize = cipher.getOutputSize(data.size)
            val output = ByteArray(outputSize)
            val len = cipher.processBytes(data, 0, data.size, output, 0)
            cipher.doFinal(output, len)

            val encryptedDataSize = output.size - MIC_SIZE
            val encryptedData = output.copyOfRange(0, encryptedDataSize)
            val mic = output.copyOfRange(encryptedDataSize, output.size)

            return Pair(encryptedData, mic)
        } catch (e: Exception) {
            return null
        }
    }

    /**
     * Déchiffre un segment de données avec AES-CCM-128.
     * 
     * @param encryptedData Les données chiffrées.
     * @param key La clé AES-128.
     * @param iv Le vecteur d'initialisation.
     * @param mic Le MIC pour vérifier l'intégrité.
     * @return Les données déchiffrées, ou null en cas d'échec.
     */
    fun decryptAesCcm(
        encryptedData: ByteArray, 
        key: ByteArray, 
        iv: ByteArray, 
        mic: ByteArray
    ): ByteArray? {
        if (
            encryptedData.size > PAYLOAD_MAX_SIZE
            || key.size != AES_KEY_SIZE
            || iv.size != IV_SIZE
            || mic.size != MIC_SIZE
        ) {
            return null
        }

        try {
            val cipher = CCMBlockCipher(AESEngine())
            val aeadParams = AEADParameters(KeyParameter(key), MIC_SIZE * 8, iv)
            cipher.init(false, aeadParams)

            val input = encryptedData + mic
            val outputSize = cipher.getOutputSize(input.size)
            val output = ByteArray(outputSize)
            
            val len = cipher.processBytes(input, 0, input.size, output, 0)
            cipher.doFinal(output, len)

            return output.copyOfRange(0, encryptedData.size)
        } catch (e: Exception) {
            return null
        }
    }

    /**
     * Construit un IV pour AES-CCM.
     */
    fun buildIV(list: Int, senderId: Int, channelId: Int, random: Long): ByteArray {
        return ByteBuffer.allocate(IV_SIZE).order(ByteOrder.LITTLE_ENDIAN)
            .putShort(list.toShort())
            .putShort(senderId.toShort())
            .putShort(channelId.toShort())
            .putInt(random.toInt())
            .array()
    }
}

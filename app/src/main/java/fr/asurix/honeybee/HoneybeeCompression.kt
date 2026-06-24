// Kotlin 1.9
// Gradle 8.5
// ---------------------------------------------------------------------------
package fr.asurix.honeybee


import android.util.Log

import java.io.ByteArrayOutputStream
import java.util.zip.Deflater
import java.util.zip.Inflater


/**
 * Gestionnaire de la compression de données.
 */
object HoneybeeCompression {
    private const val TAG = "HoneybeeCompression"

    private const val FLAG_RAW: Byte = 0x00
    private const val FLAG_COMPRESSED: Byte = 0x01

    const val MIN_COMPRESSION_THRESHOLD = 50

    /**
     * Compresse des données avec Deflate (mode No Wrap).
     * 
     * @param data Les données à compresser.
     * @return [Flag (1 byte)] + [Données (Brutes ou Compressées)].
     */
    fun compress(data: ByteArray): ByteArray? {
        if (data.isEmpty() || data.size < MIN_COMPRESSION_THRESHOLD) {
            return byteArrayOf(FLAG_RAW) + data
        }

        return try {
            val deflater = Deflater(Deflater.BEST_COMPRESSION, true) // true = mode "nowrap"
            deflater.setInput(data)
            deflater.finish()

            val outputStream = ByteArrayOutputStream(data.size)
            val buffer = ByteArray(256)

            while (!deflater.finished()) {
                val count = deflater.deflate(buffer)
                outputStream.write(buffer, 0, count)
            }
            deflater.end()

            val compressedData = outputStream.toByteArray()

            if (compressedData.size >= data.size) {
                return byteArrayOf(FLAG_RAW) + data
            }

            byteArrayOf(FLAG_COMPRESSED) + compressedData
        } catch (e: Exception) {
            Log.e(TAG, "Erreur lors de la compression", e)
            null
        }
    }

    /**
     * Décompresse des données encodées avec Deflate (mode RAW).
     * 
     * @param data Le payload complet reçu sur le réseau (incluant le flag).
     * @return Les données déchiffrées et décompressées, ou null en cas d'échec.
     */
    fun decompress(data: ByteArray): ByteArray? {
        if (data.isEmpty()) return data

        val flag = data[0]
        data = data.copyOfRange(1, data.size)

        if (flag == FLAG_RAW) {
            return data
        }

        if (flag != FLAG_COMPRESSED) {
            Log.e(TAG, "Erreur : Flag de compression inconnu ($flag)")
            return null
        }

        return try {
            val inflater = Inflater(true) // true = mode "nowrap"
            inflater.setInput(data)

            val outputStream = ByteArrayOutputStream(data.size * 2)
            val buffer = ByteArray(256)

            while (!inflater.finished()) {
                val count = inflater.inflate(buffer)
                if (count == 0 && inflater.needsInput()) {
                    Log.e(TAG, "Erreur : Fin de flux inattendue")
                    return null
                }
                outputStream.write(buffer, 0, count)
            }
            inflater.end()

            outputStream.toByteArray()
        } catch (e: Exception) {
            Log.e(TAG, "Erreur lors de la décompression Deflate", e)
            null
        }
    }
}

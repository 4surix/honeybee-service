// Kotlin 1.9
// Gradle 8.5
// ---------------------------------------------------------------------------
package fr.asurix.honeybee


import android.content.Context
import android.util.Log
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKeys

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap


/**
 * Gestionnaire des canaux Honeybee.
 * 
 * Cette classe s'occupe de la persistance sécurisée, 
 *  de la récupération en mémoire 
 *  et de la génération des clés cryptographiques associées aux différents canaux.
 * Le fichier de sauvegarde est entièrement chiffré (AES-256-GCM) 
 *  via la bibliothèque Jetpack Security et le système Android Keystore.
 * 
 * https://developer.android.com/jetpack/androidx/releases/security?hl=fr 
 * https://developer.android.com/privacy-and-security/keystore?hl=fr 
 *
 * @property context Le contexte Android.
 */
class HoneybeeChannelManager(private val context: Context) {

    companion object {
        private const val TAG = "HoneybeeChannelManager"

        private const val CHANNELS_FILE = "HoneybeeKeysChannels.dat"  // Nom du fichier de sauvegarde
        private const val CHANNEL_ENTRY_SIZE = 18                     // Channel (2) + Key (16) 
    }

    private val channels = ConcurrentHashMap<Int, HoneybeeChannel>()
    private val random = SecureRandom()

    init {
        loadChannels()
    }

    /**
     * Crée et configure une instance d'[EncryptedFile] 
     *  pour lire ou écrire de manière sécurisée.
     * La clé maîtresse est générée automatiquement 
     *  ou récupérée depuis l'Android Keystore.
     * 
     * AES : https://fr.wikipedia.org/wiki/Advanced_Encryption_Standard
     * GCM : https://fr.wikipedia.org/wiki/Galois/Counter_Mode
     * 
     */
    private fun getEncryptedFile(): EncryptedFile {
        val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)

        val file = File(context.filesDir, CHANNELS_FILE)

        return EncryptedFile.Builder(
            file,
            context,
            masterKeyAlias,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_SPEC
        ).build()
    }

    /**
     * Récupère un canal spécifique à partir de son identifiant.
     *
     * @param channelId L'identifiant unique du canal.
     * @return Le [HoneybeeChannel] correspondant, ou null s'il n'existe pas.
     */
    fun getChannel(channelId: Int): HoneybeeChannel? {
        return channels[channelId]
    }

    /**
     * Ajoute ou met à jour un canal en mémoire, 
     *  puis déclenche une sauvegarde chiffrée.
     *
     * @param channel Le canal à enregistrer.
     */
    fun addChannel(channel: HoneybeeChannel) {
        channels[channel.id] = channel
        saveChannels()
    }

    /**
     * Supprime un canal de la mémoire 
     *  et met à jour le fichier chiffré sur le disque.
     *
     * @param channelId L'identifiant du canal à supprimer.
     */
    fun removeChannel(channelId: Int) {
        if (channels.remove(channelId) != null) {
            saveChannels()
        }
    }

    /**
     * Retourne la liste complète de tous les canaux actuellement chargés.
     *
     * @return Une liste d'objets [HoneybeeChannel].
     */
    fun getAllChannels(): List<HoneybeeChannel> {
        return channels.values.toList()
    }

    /**
     * Retourne la liste complète des identifiants des canaux enregistrés.
     *
     * @return Une liste d'entiers représentant les IDs.
     */
    fun getAllChannelIds(): List<Int> {
        return channels.keys.toList()
    }

    /**
     * Vérifie si un canal spécifique est présent en mémoire.
     *
     * @param channelId L'identifiant du canal à vérifier.
     * @return Vrai si le canal existe, faux sinon.
     */
    fun hasChannel(channelId: Int): Boolean {
        return channels.containsKey(channelId)
    }

    /**
     * Génère une nouvelle clé de chiffrement symétrique AES-128.
     *
     * @return Un tableau de 16 octets aléatoires.
     */
    fun generateAesKey(): ByteArray {
        val key = ByteArray(16)
        random.nextBytes(key)
        return key
    }

    /**
     * Déchiffre et charge les canaux depuis le fichier local lors de l'initialisation.
     */
    private fun loadChannels() {
        val file = File(context.filesDir, CHANNELS_FILE)

        if (!file.exists()) {
            Log.d(TAG, "Aucun fichier de canaux trouvé.")
            return
        }

        try {
            getEncryptedFile().openFileInput().bufferedReader().use { reader ->
                reader.forEachLine { line ->
                    if (line.isNotBlank()) {
                        val bytes = line.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                        if (bytes.size >= CHANNEL_ENTRY_SIZE) {
                            parseChannel(bytes)
                        } else {
                            Log.w(TAG, "Taille de ligne invalide ignorée : ${bytes.size} octets")
                        }
                    }
                }
            }
            Log.d(TAG, "Chargement sécurisé de ${channels.size} canaux réussi.")
        } catch (e: Exception) {
            Log.e(TAG, "Erreur lors du déchiffrement/chargement des canaux", e)
        }
    }

    /**
     * Extrait les informations d'un canal depuis un tableau d'octets brut
     *  et l'ajoute au cache.
     */
    private fun parseChannel(bytes: ByteArray) {
        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)

        val id = buffer.short.toInt() and 0xFFFF
        
        val encryptionKey = ByteArray(16)
        buffer.get(encryptionKey)

        val channel = HoneybeeChannel(
            id = id,
            encryptionKey = encryptionKey
        )

        channels[id] = channel
    }

    /**
     * Sauvegarde et chiffre l'état actuel de tous les canaux 
     *  vers le fichier local.
     */
    private fun saveChannels() {
        try {
            val file = File(context.filesDir, CHANNELS_FILE)
            
            // EncryptedFile ne supporte pas (apparement) l'écrasement direct 
            //  si le fichier existe déjà, il est recommandé de supprimer l'ancien fichier 
            //  avant d'écrire la nouvelle version chiffrée.
            if (file.exists()) {
                file.delete()
            }

            getEncryptedFile().openFileOutput().bufferedWriter().use { writer ->
                channels.values.forEach { channel ->
                    val bytes = channelToBytes(channel)
                    writer.write(bytes.joinToString("") { "%02x".format(it) })
                    writer.newLine()
                }
            }
            Log.d(TAG, "Sauvegarde chiffrée de ${channels.size} canaux effectuée.")
        } catch (e: Exception) {
            Log.e(TAG, "Erreur lors du chiffrement/sauvegarde des canaux", e)
        }
    }

    /**
     * Sérialise un objet [HoneybeeChannel] en tableau d'octets de taille fixe.
     */
    private fun channelToBytes(channel: HoneybeeChannel): ByteArray {
        return ByteBuffer
            .allocate(CHANNEL_ENTRY_SIZE)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putShort(channel.id.toShort())
            .put(channel.encryptionKey)
            .array()
    }
}

// Kotlin 1.9
// Gradle 8.5
// ---------------------------------------------------------------------------
package com.honeybee.service

import android.util.Log
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Classe de base pour tous les paquets Honeybee.
 * 
 * @property id ID du protocole.
 * @property type Type du paquet.
 */
sealed class HoneybeePacket(
    val id: Int,          // 5 bits
    val type: PacketType  // 3 bits
) {
    companion object {
        private const val TAG = "HoneybeePacket"
        private const val PROTOCOL_ID = 0b10100 // 5 bits
        private const val HEADER_SIZE = 1       // 1 byte

        /**
         * Parse un paquet brut en sous-classe HoneybeePacket.
         *
         * @param data Données brutes du paquet (reçues via BLE).
         * @return Instance de HoneybeePacket ou null si le paquet est invalide.
         */
        fun fromBytes(data: ByteArray): HoneybeePacket? {
            if (data.size < HEADER_SIZE) {
                Log.e(TAG, "Paquet trop court (${data.size} bytes)")
                return null
            }

            val header = ByteBuffer.wrap(data, 0, HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFF

            val id = (header shr 11) and 0b11111
            if (id != PROTOCOL_ID) {
                Log.e(TAG, "ID du protocole invalide (attendu: $PROTOCOL_ID, reçu: $id)")
                return null
            }

            val typeBits = (header shr 8) and 0b111
            val type = PacketType.fromBits(typeBits) ?: run {
                Log.e(TAG, "Type de paquet invalide: $typeBits")
                return null
            }

            return when (type) {
                PacketType.INFORMATIONS -> InformationPacket.fromBytes(data)
                PacketType.NEIGHBOR -> NeighborPacket.fromBytes(data)
                PacketType.MESSAGE -> MessagePacket.fromBytes(data)
                PacketType.ACK -> AckPacket.fromBytes(data)
            }
        }
    }

    /**
     * Convertit le paquet en bytes pour l'envoi via BLE Advertising.
     * Chaque sous-classe implémente cette méthode.
     */
    abstract fun toBytes(): ByteArray
}

/**
 * Paquet de type Informations.
 * Contient la liste des voisins primaires du noeud émetteur.
 *
 * @property senderId ID numérique de l'expéditeur, 0x0000 à 0xFFFF.
 * @property role Rôle du noeud (0x01: Primary, 0x02: Secondary).
 * @property score Score du noeud (0-100).
 * @property neighborCount Nombre total de voisins.
 * @property primaryCount Nombre de Primary Nodes voisins.
 * @property primaryDevices Liste des IDs des Primary Nodes voisins (max 12).
 */
data class InformationPacket(
    val senderId: Int,              // 2 bytes
    val role: Int,                  // 1 byte
    val score: Int,                 // 1 byte
    val neighborCount: Int,         // 1 byte
    val primaryCount: Int,          // 1 byte
    val primaryDevices: List<Int>
) : HoneybeePacket(
    id = PROTOCOL_ID,
    type = PacketType.INFORMATIONS
) {
    companion object {
        // Header (1) + Sender (2) + Role (1) + Score (1) + Neighbor (1) + Primary (1)
        private const val MIN_SIZE = 7 

        /**
         * Parse un paquet de type Informations.
         */
        fun fromBytes(data: ByteArray): InformationPacket? {
            if (data.size < MIN_SIZE) {
                Log.e(TAG, "Paquet Informations trop court (${data.size} bytes)")
                return null
            }

            val offset = HEADER_SIZE
            val senderId = 
                ByteBuffer
                .wrap(data, offset, 2)
                .order(ByteOrder.LITTLE_ENDIAN)
                .short.toInt() and 0xFFFF
            val role = 
                data[offset + 2].toInt() and 0xFF
            val score = 
                data[offset + 3].toInt() and 0xFF
            val neighborCount = 
                data[offset + 4].toInt() and 0xFF
            val primaryCount = 
                data[offset + 5].toInt() and 0xFF

            val primaryDevices = mutableListOf<Int>()
            val primaryDevicesStart = offset + 6
            val primaryDevicesEnd = minOf(primaryDevicesStart + 24, data.size)
            for (i in primaryDevicesStart until primaryDevicesEnd step 2) {
                if (i + 2 <= data.size) {
                    val primaryId = 
                        ByteBuffer
                        .wrap(data, i, 2)
                        .order(ByteOrder.LITTLE_ENDIAN)
                        .short.toInt() and 0xFFFF
                    primaryDevices.add(primaryId)
                }
            }

            return InformationPacket(
                senderId = senderId,
                role = role,
                score = score,
                neighborCount = neighborCount,
                primaryCount = primaryCount,
                primaryDevices = primaryDevices
            )
        }
    }

    override fun toBytes(): ByteArray {
        val buffer = ByteBuffer.allocate(31).order(ByteOrder.LITTLE_ENDIAN)

        buffer.put((id shl 11) or (type.bits shl 8))
        buffer.putShort(senderId.toShort())
        buffer.put(role.toByte())
        buffer.put(score.toByte())
        buffer.put(neighborCount.toByte())
        buffer.put(primaryCount.toByte())

        primaryDevices.forEach { primaryId ->
            buffer.putShort(primaryId.toShort())
        }

        return buffer.array().copyOfRange(0, buffer.position())
    }
}

/**
 * Paquet de type Neighbor.
 * Contient la liste des voisins secondaires du noeud émetteur.
 *
 * @property senderId ID numérique de l'expéditeur, 0x0000 à 0xFFFF.
 * @property neighborDeviceCount Nombre de voisins dans le paquet.
 * @property neighborDevices Liste des IDs des voisins (max 13).
 */
data class NeighborPacket(
    val senderId: Int,                // 2 bytes
    val neighborDeviceCount: Int,     // 1 byte
    val neighborDevices: List<Int>    
) : HoneybeePacket(
    id = PROTOCOL_ID,
    type = PacketType.NEIGHBOR
) {
    companion object {
        // Header (1) + Sender (2) + Neighbor Count (1)
        private const val MIN_SIZE = 5

        /**
         * Parse un paquet de type Neighbor.
         */
        fun fromBytes(data: ByteArray, ttl: Int, senderId: Int): NeighborPacket? {
            if (data.size < MIN_SIZE) {
                Log.e(TAG, "Paquet Neighbor trop court (${data.size} bytes)")
                return null
            }

            val offset = HEADER_SIZE + 2
            val senderId = 
                ByteBuffer
                .wrap(data, offset, 2)
                .order(ByteOrder.LITTLE_ENDIAN)
                .short.toInt() and 0xFFFF
            val neighborDeviceCount = 
                data[offset + 2].toInt() and 0xFF

            val neighborDevices = mutableListOf<Int>()
            val neighborDevicesStart = offset + 1
            val neighborDevicesEnd = minOf(neighborDevicesStart + 26, data.size)
            for (i in neighborDevicesStart until neighborDevicesEnd step 2) {
                if (i + 2 <= data.size) {
                    val neighborId =
                        ByteBuffer
                        .wrap(data, i, 2)
                        .order(ByteOrder.LITTLE_ENDIAN)
                        .short.toInt() and 0xFFFF
                    neighborDevices.add(neighborId)
                }
            }

            return NeighborPacket(
                neighborDeviceCount = neighborDeviceCount,
                neighborDevices = neighborDevices,
                ttl = ttl,
                senderId = senderId
            )
        }
    }

    override fun toBytes(): ByteArray {
        val buffer = ByteBuffer.allocate(31).order(ByteOrder.LITTLE_ENDIAN)

        buffer.put((id shl 11) or (type.bits shl 8))
        buffer.putShort(senderId.toShort())
        buffer.put(neighborDeviceCount.toByte())

        neighborDevices.forEach { neighborId ->
            buffer.putShort(neighborId.toShort())
        }

        return buffer.array().copyOfRange(0, buffer.position())
    }
}

/**
 * Paquet de type Message.
 * Contient un message fragmenté et chiffré.
 *
 * @property ttl Le nombre de fois que le paquet peut être relayé.
 * @property list Champ List.
 * @property senderId ID numérique de l'expéditeur, 0x0000 à 0xFFFF.
 * @property channelId ID du canal.
 * @property random Nombre aléatoire pour l'IV.
 * @property mic AES-CCM MIC.
 * @property payload Données chiffrées.
 */
data class MessagePacket(
    val ttl: Int,            // 8 bits (0-255)
    val list: Int,           // 2 bytes (Chain: 4 bits, Last: 6 bits, Index: 6 bits)
    val senderId: Int,       // 2 bytes 
    val channelId: Int,      // 2 bytes
    val random: Int,         // 4 bytes 
    val mic: ByteArray,      // 6 bytes 
    val payload: ByteArray   // 1-13 bytes
) : HoneybeePacket(
    id = PROTOCOL_ID,
    type = PacketType.MESSAGE
) {
    companion object {
        // Header (1) + TTL (1) + List (2) + Sender (2) + Channel (2) + Random (4) + MIC (5) + Payload (1)
        private const val MIN_SIZE = 18

        /**
         * Parse un paquet de type Message.
         */
        fun fromBytes(data: ByteArray): MessagePacket? {
            if (data.size < MIN_SIZE) {
                Log.e(TAG, "Paquet Message trop court (${data.size} bytes)")
                return null
            }

            val offset = HEADER_SIZE
            val ttl = data[offset].toInt() and 0xFF
            val list = 
                ByteBuffer.wrap(data, offset + 1, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
            val senderId = 
                ByteBuffer.wrap(data, offset + 3, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
            val channelId = 
                ByteBuffer.wrap(data, offset + 5, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
            val random = 
                ByteBuffer.wrap(data, offset + 7, 4).order(ByteOrder.LITTLE_ENDIAN).int
            val mic = 
                data.copyOfRange(offset + 11, offset + 16)
            val payload = 
                data.copyOfRange(offset + 16, data.size)

            return MessagePacket(
                ttl = ttl,
                list = list,
                senderId = senderId
                channelId = channelId
                random = random,
                mic = mic,
                payload = payload
            )
        }
    }

    override fun toBytes(): ByteArray {
        val buffer = ByteBuffer.allocate(31).order(ByteOrder.LITTLE_ENDIAN)

        buffer.put((id shl 11) or (type.bits shl 8))
        buffer.put(ttl.toByte())
        buffer.putShort(list.toShort())
        buffer.putShort(senderId.toShort())
        buffer.putShort(channelId.toShort())
        buffer.putInt(random)
        buffer.put(mic)
        buffer.put(payload)

        return buffer.array().copyOfRange(0, buffer.position())
    }
}

/**
 * Paquet de type ACK.
 *
 * @property senderId ID numérique de l'expéditeur, 0x0000 à 0xFFFF.
 * @property listPacket Champ List du paquet concerné.
 * @property senderPacket ID numérique de l'expéditeur du paquet concerné.
 * @property channelPacket ID du canal.
 * @property ackType Type d'ACK.
 */
data class AckPacket(
    val senderId: Int         // 2 bytes
    val listPacket: Int,      // 2 bytes
    val senderPacket: Int,    // 2 bytes
    val channelPacket: Int,   // 2 bytes
    val ackType: AckType 
) : HoneybeePacket(
    id = PROTOCOL_ID,
    type = PacketType.ACK
) {
    companion object {
        // Header (1) + Sender (2) + Packet ID (6) + AckType (1)
        private const val SIZE = 10

        /**
         * Parse un paquet de type ACK.
         */
        fun fromBytes(data: ByteArray, ttl: Int, senderId: Int): AckPacket? {
            if (data.size < SIZE) {
                Log.e(TAG, "Paquet ACK trop court (${data.size} bytes, attendu: $SIZE)")
                return null
            }

            val offset = HEADER_SIZE
            val senderId = 
                ByteBuffer.wrap(data, offset, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
            val listPacket = 
                ByteBuffer.wrap(data, offset + 2, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
            val senderPacket = 
                ByteBuffer.wrap(data, offset + 4, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
            val channelPacket = 
                ByteBuffer.wrap(data, offset + 6, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
            val ackTypeValue = data[offset + 8].toInt() and 0xFF
            val ackType = AckType.fromValue(ackTypeValue) ?: run {
                Log.e(TAG, "Type d'ACK invalide: $ackTypeValue")
                return null
            }

            return AckPacket(
                senderId = senderId,
                listPacket = listPacket,
                senderPacket = senderPacket,
                channelPacket = channelPacket,
                ackType = ackType
            )
        }
    }

    override fun toBytes(): ByteArray {
        val buffer = ByteBuffer.allocate(31).order(ByteOrder.LITTLE_ENDIAN)

        buffer.put((id shl 11) or (type.bits shl 8))
        buffer.putShort(senderId.toShort())
        buffer.putShort(listPacket.toShort())
        buffer.putShort(senderPacket.toShort())
        buffer.putShort(channelPacket.toShort())
        buffer.put(ackType.value.toByte())

        return buffer.array().copyOfRange(0, buffer.position())
    }
}

/**
 * Types de paquets Honeybee.
 */
enum class PacketType(val bits: Int) {
    INFORMATIONS(0b001),
    NEIGHBOR(0b010),
    MESSAGE(0b011),
    ACK(0b100);

    companion object {
        fun fromBits(bits: Int): PacketType? {
            return values().find { it.bits == bits }
        }
    }
}

/**
 * Types d'ACK Honeybee.
 * Utilisé dans le champ ackType de AckPacket.
 */
enum class AckType(val value: Int) {
    MISSING(0x01),    // Le device n'a pas reçu le paquet
    UNABLED(0x03),    // Le device ne peut pas traiter le paquet
    DENIED(0x07),     // Le device ne veut pas traiter le paquet
    DUPLICATED(0x0F), // Le device a déjà reçu ce paquet
    SUCCEEDED(0x1F),  // Le device a reçu tout le groupe de paquets
    CONFIRMED(0x3F);  // Le device a reçu le ACK Succeeded

    companion object {
        fun fromValue(value: Int): AckType? = values().find { it.value == value }
    }
}

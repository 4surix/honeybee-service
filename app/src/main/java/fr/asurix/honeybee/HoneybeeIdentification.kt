// Kotlin 1.9
// Gradle 8.5
// ---------------------------------------------------------------------------
package fr.asurix.honeybee


import android.util.Log

import java.util.UUID


/**
 * Génère un nouvel identifiant toutes les 15 minutes en utilisant un LFSR 16 bits.
 */
class HoneybeeIdentification {
    companion object {
        private const val TAG = "HoneybeeIdentification"

        private const val PERIOD_DURATION = 15 * 60 * 1000L // 15 minutes en ms
        private const val LFSR_POLYNOMIAL = 0x402B          // Polynôme pour le LFSR
    }

    private val deviceUuid: UUID = UUID.randomUUID()

    private var currentPeriodIndex: Int = -1 
    private var currentSenderId: Int = 0

    init {
        updateSenderIdIfNeeded()
    }

    /**
     * Récupère l'ID de l'expéditeur actuel.
     */
    @Synchronized
    fun getCurrentSenderId(): Int {
        updateSenderIdIfNeeded()
        return currentSenderId
    }

    /**
     * Force la régénération de l'ID.
     */
    @Synchronized
    fun regenerateSenderId() {
        val currentPeriod = getCurrentGlobalPeriod()
        generateAndSetId(currentPeriod)
        Log.d(TAG, "ID régénéré manuellement : $currentSenderId")
    }

    /**
     * Vérifie si l'on a changé de période de 15 minutes sur l'horloge globale.
     */
    private fun updateSenderIdIfNeeded() {
        val currentPeriod = getCurrentGlobalPeriod()
        if (currentPeriod != currentPeriodIndex || currentSenderId == 0) {
            generateAndSetId(currentPeriod)
        }
    }

    private fun getCurrentGlobalPeriod(): Int {
        return (System.currentTimeMillis() / PERIOD_DURATION).toInt()
    }

    /**
     * Génère et met en cache un nouvel identifiant d'expéditeur.
     */
    private fun generateAndSetId(period: Int) {
        currentPeriodIndex = period

        val period8bits = period and 0xFF 
        var seed = (deviceUuid.leastSignificantBits and 0xFFFF).toInt()

        if (seed == 0) seed = 1 

        val finalState = lfsr(seed, period8bits)
        val byte1 = (finalState shr 8) xor period8bits
        val byte2 = (finalState and 0xFF) xor period8bits

        currentSenderId = (byte1 shl 8) or byte2

        Log.d(TAG, "Nouvel ID généré : $currentSenderId (Période: $period8bits, Hex: ${"%04X".format(currentSenderId)})")
    }

    /**
     * Applique un LFSR de Galois sur une graine donnée.
     * 
     * https://fr.wikipedia.org/wiki/Registre_%C3%A0_d%C3%A9calage_%C3%A0_r%C3%A9troaction_lin%C3%A9aire 
     * https://defeo.lu/in420/Bit%20twiddling%20et%20LFSR
     */
    private fun lfsr(initialSeed: Int, periods: Int): Int {
        var state = initialSeed
        repeat(periods) {
            val lsb = state and 1 // Regarde le bit sortant
            state = state ushr 1  // Décale tout les bits vers la droite
            if (lsb == 1) {       // Si le bit sortant est 1, on applique le masque polynomial via XOR
                state = state xor LFSR_POLYNOMIAL
            }
        }
        return state and 0xFFFF
    }
}

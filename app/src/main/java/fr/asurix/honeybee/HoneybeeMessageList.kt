// Kotlin 1.9
// Gradle 8.5
// ---------------------------------------------------------------------------
package fr.asurix.honeybee


import android.util.Log


/**
 * Gére le champ List des paquets de type Message.
 */
class HoneybeeMessageList (
    val chainId: Int,
    val lastIndex: Int,
    val currentIndex: Int
) {
    companion object {

        private const val TAG = "HoneybeeMessageList"

        /**
         * Parse le champ List (Chain, Last, Index).
         */
        fun parseField(listField: Int): Triple<Int, Int, Int> {
            val chainId = (listField shr 12) and 0xF
            val lastIndex = (listField shr 6) and 0x3F
            val currentIndex = listField and 0x3F
            return HoneybeeMessageList(chainId, lastIndex, currentIndex)
        }

    }

    /**
     * Construit le champ List (Chain: 4 bits, Last: 6 bits, Index: 6 bits).
     */
    fun buildField(): Int? {
        return if (chainId in 0..15 || lastIndex in 0..63 || currentIndex in 0..63) {
            (chainId shl 12) or (lastIndex shl 6) or currentIndex
        } else {
            null
        }
    }
}

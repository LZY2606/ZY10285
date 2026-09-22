package prism

import java.math.BigInteger
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

enum class Mode(val label: String) {
    BER("BER 宽松读取"),
    CER("CER 检查"),
    DER("DER 检查");

    companion object {
        fun of(s: String?): Mode = entries.firstOrNull { it.name.equals(s, true) } ?: BER
    }
}

data class Finding(val nodeId: Int, val path: String, val level: String, val message: String)

object Tags {
    const val BOOLEAN = 1L
    const val INTEGER = 2L
    const val BIT_STRING = 3L
    const val OCTET_STRING = 4L
    const val NULL = 5L
    const val OID = 6L
    const val ENUMERATED = 10L
    const val UTF8_STRING = 12L
    const val SEQUENCE = 16L
    const val SET = 17L
    const val NUMERIC_STRING = 18L
    const val PRINTABLE_STRING = 19L
    const val TELETEX_STRING = 20L
    const val IA5_STRING = 22L
    const val UTC_TIME = 23L
    const val GENERALIZED_TIME = 24L
    const val VISIBLE_STRING = 26L
    const val GENERAL_STRING = 27L
    const val UNIVERSAL_STRING = 28L
    const val BMP_STRING = 30L

    val universalNames = mapOf(
        BOOLEAN to "BOOLEAN", INTEGER to "INTEGER", BIT_STRING to "BIT STRING",
        OCTET_STRING to "OCTET STRING", NULL to "NULL", OID to "OBJECT IDENTIFIER",
        ENUMERATED to "ENUMERATED", UTF8_STRING to "UTF8String",
        SEQUENCE to "SEQUENCE", SET to "SET", NUMERIC_STRING to "NumericString",
        PRINTABLE_STRING to "PrintableString", TELETEX_STRING to "TeletexString",
        IA5_STRING to "IA5String", UTC_TIME to "UTCTime",
        GENERALIZED_TIME to "GeneralizedTime", VISIBLE_STRING to "VisibleString",
        GENERAL_STRING to "GeneralString", UNIVERSAL_STRING to "UniversalString",
        BMP_STRING to "BMPString",
    )

    /** String types that CER allows to be constructed & chunked. */
    val restrictedStringTags = setOf(
        OCTET_STRING, NUMERIC_STRING, PRINTABLE_STRING, TELETEX_STRING,
        IA5_STRING, VISIBLE_STRING, GENERAL_STRING, UNIVERSAL_STRING, BMP_STRING, UTF8_STRING,
    )

    fun isStringLike(node: Node): Boolean =
        node.tagClass == TagClass.UNIVERSAL &&
            (node.tagNumber == BIT_STRING || node.tagNumber in restrictedStringTags)

    /** False for anything we cannot safely re-encode: non-universal classes and
     *  universal tags outside the known table are preserved byte-for-byte. */
    fun isKnown(node: Node): Boolean =
        node.tagClass == TagClass.UNIVERSAL && node.tagNumber in universalNames

    fun nameOf(node: Node): String =
        if (node.tagClass == TagClass.UNIVERSAL)
            universalNames[node.tagNumber] ?: "universal-${node.tagNumber}"
        else "[${node.tagClass.label} ${node.tagNumber}]"
}

object Decoders {
    fun decode(node: Node, data: ByteArray): String? {
        if (node.tagClass != TagClass.UNIVERSAL || node.constructed) return null
        val c = data.copyOfRange(node.contentOffset, node.contentEnd)
        return when (node.tagNumber) {
            Tags.BOOLEAN -> when {
                c.size != 1 -> "BOOLEAN（长度 ${c.size}，应为 1）"
                c[0].toInt() == 0 -> "FALSE"
                else -> "TRUE"
            }
            Tags.INTEGER, Tags.ENUMERATED ->
                if (c.isEmpty()) "（空内容）" else BigInteger(c).toString()
            Tags.BIT_STRING ->
                if (c.isEmpty()) "（缺少 unused-bits 字节）"
                else "unused=${c[0].toInt() and 0xFF} bits=${c.copyOfRange(1, c.size).hex().ifEmpty { "∅" }}"
            Tags.OID -> decodeOid(c)
            Tags.UTC_TIME, Tags.GENERALIZED_TIME, Tags.UTF8_STRING, Tags.PRINTABLE_STRING,
            Tags.IA5_STRING, Tags.VISIBLE_STRING, Tags.NUMERIC_STRING, Tags.TELETEX_STRING,
            Tags.GENERAL_STRING ->
                String(c, Charsets.UTF_8)
            else -> null
        }
    }

    fun decodeOid(c: ByteArray): String {
        if (c.isEmpty()) return "（空 OID）"
        val subs = mutableListOf<Long>()
        var i = 0
        while (i < c.size) {
            var v = 0L
            var more = true
            while (more && i < c.size) {
                val b = c[i].toInt() and 0xFF
                i++
                if (v > (Long.MAX_VALUE - (b and 0x7F)) / 128) return "（OID 子标识符溢出）"
                v = v * 128 + (b and 0x7F)
                more = b and 0x80 != 0
            }
            if (more) return "（OID 被截断）"
            subs += v
        }
        val first = subs[0]
        val arc0 = if (first < 40) 0 else if (first < 80) 1 else 2
        val arc1 = if (arc0 < 2) first - arc0 * 40 else first - 80
        return (listOf(arc0.toLong(), arc1) + subs.drop(1)).joinToString(".")
    }
}

object Checks {
    fun run(result: ParseResult, mode: Mode): List<Finding> {
        val findings = mutableListOf<Finding>()
        fun walk(node: Node, path: String) {
            node.errors.forEach { findings += Finding(node.id, path, "ERROR", it) }
            if (mode != Mode.BER) {
                lengthFindings(node, mode).forEach { findings += Finding(node.id, path, it.first, it.second) }
                valueFindings(node, result.data, mode).forEach { findings += Finding(node.id, path, "ERROR", it) }
                if (mode == Mode.CER) cerFindings(node, result.data).forEach { findings += Finding(node.id, path, "ERROR", it) }
                if (mode == Mode.DER) derFindings(node).forEach { findings += Finding(node.id, path, "ERROR", it) }
            }
            node.children.forEachIndexed { i, child -> walk(child, "$path/$i") }
        }
        result.roots.forEachIndexed { i, root -> walk(root, "$i") }
        return findings
    }

    private fun lengthFindings(node: Node, mode: Mode): List<Pair<String, String>> {
        val out = mutableListOf<Pair<String, String>>()
        val len = node.length
        if (len is Len.Definite && node.lengthRaw.size > 1) {
            val k = node.lengthRaw.size - 1
            val first = node.lengthRaw[1].toInt() and 0xFF
            when {
                len.n < 128 -> out += "ERROR" to "长度 ${len.n} 应使用短形式，而非 $k 字节长形式"
                first == 0 -> out += "ERROR" to "长度长形式含冗余前导 0x00，非最短形式"
            }
        }
        if (mode == Mode.DER && len is Len.Indefinite) out += "ERROR" to "DER 不允许不定长度"
        if (mode == Mode.CER && len is Len.Indefinite && !node.constructed)
            out += "ERROR" to "CER 原始类型必须使用定长"
        if (mode == Mode.CER && len is Len.Definite && node.constructed && Tags.isKnown(node))
            out += "ERROR" to "CER 构造类型必须使用不定长度 + EOC"
        return out
    }

    private fun valueFindings(node: Node, data: ByteArray, mode: Mode): List<String> {
        if (node.tagClass != TagClass.UNIVERSAL) return emptyList()
        val c = data.copyOfRange(node.contentOffset, node.contentEnd)
        val out = mutableListOf<String>()
        when (node.tagNumber) {
            Tags.INTEGER, Tags.ENUMERATED -> {
                if (c.isEmpty()) out += "INTEGER 内容为空"
                else if (!isMinimalTwosComplement(c))
                    out += "INTEGER 非最小补码：存在冗余前导字节"
            }
            Tags.BOOLEAN -> {
                if (c.size != 1) out += "BOOLEAN 长度必须为 1"
                else if (c[0].toInt() != 0 && c[0].toInt() != 0xFF)
                    out += "BOOLEAN 必须为 0x00 或 0xFF，实际 0x%02X".format(c[0])
            }
            Tags.BIT_STRING -> {
                if (c.isEmpty()) out += "BIT STRING 缺少 unused-bits 字节"
                else {
                    val unused = c[0].toInt() and 0xFF
                    if (unused > 7) out += "BIT STRING unused bits = $unused，超过 7"
                    if (c.size == 1 && unused != 0) out += "空 BIT STRING 的 unused bits 必须为 0"
                    if (c.size > 1 && unused > 0) {
                        val mask = (1 shl unused) - 1
                        if (c.last().toInt() and mask != 0)
                            out += "BIT STRING 未用位未清零（DER/CER 要求为 0）"
                    }
                }
            }
            Tags.OID -> out += oidFindings(c)
            Tags.UTC_TIME -> out += timeFindings(c, utc = true)
            Tags.GENERALIZED_TIME -> out += timeFindings(c, utc = false)
        }
        return out
    }

    fun isMinimalTwosComplement(c: ByteArray): Boolean {
        if (c.size < 2) return true
        val b0 = c[0].toInt() and 0xFF
        val b1 = c[1].toInt() and 0xFF
        return !((b0 == 0x00 && b1 < 0x80) || (b0 == 0xFF && b1 >= 0x80))
    }

    fun oidFindings(c: ByteArray): List<String> {
        if (c.isEmpty()) return listOf("OID 内容为空")
        val out = mutableListOf<String>()
        var i = 0
        while (i < c.size) {
            val start = i
            while (i < c.size && c[i].toInt() and 0x80 != 0) i++
            if (i >= c.size) { out += "OID 最后一个子标识符被截断"; return out }
            if (c[start].toInt() and 0xFF == 0x80 && i > start)
                out += "OID 子标识符（偏移 $start）非最短 base-128 形式"
            i++
        }
        return out
    }

    private val utcRe = Regex("""^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(Z|[+-]\d{4})$""")
    private val genRe = Regex("""^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(\.\d+)?(Z|[+-]\d{4})$""")

    fun timeFindings(c: ByteArray, utc: Boolean): List<String> {
        val s = String(c, Charsets.US_ASCII)
        val m = (if (utc) utcRe else genRe).matchEntire(s)
            ?: return listOf("时间格式非法：$s")
        val out = mutableListOf<String>()
        if (m.groupValues.last() != "Z") out += "DER/CER 要求时间为 UTC（Z 结尾），实际带时区 ${m.groupValues.last()}"
        if (utc && m.groupValues[6].isEmpty()) out += "DER/CER 要求 UTCTime 包含秒"
        if (!utc && m.groupValues[7].isNotEmpty()) out += "DER/CER 不允许 GeneralizedTime 小数秒"
        return out
    }

    private fun cerFindings(node: Node, data: ByteArray): List<String> {
        val out = mutableListOf<String>()
        if (Tags.isStringLike(node) && node.tagClass == TagClass.UNIVERSAL) {
            val flat = flattenContent(node, data)
            if (!node.constructed && flat.size > 1000)
                out += "CER 要求超过 1000 字节的字符串使用构造分片"
            if (node.constructed) {
                node.children.forEachIndexed { i, ch ->
                    if (ch.tagNumber != node.tagNumber || ch.tagClass != TagClass.UNIVERSAL || ch.constructed)
                        out += "CER 分片 ${i} 必须是同 tag 的原始类型"
                    else {
                        val n = ch.contentEnd - ch.contentOffset
                        if (i < node.children.size - 1 && n != 1000)
                            out += "CER 分片界限：第 ${i} 片为 $n 字节，应为 1000"
                        if (i == node.children.size - 1 && (n < 1 || n > 1000))
                            out += "CER 最后一片为 $n 字节，应在 1..1000"
                    }
                }
            }
        }
        return out
    }

    private fun derFindings(node: Node): List<String> {
        val out = mutableListOf<String>()
        if (Tags.isStringLike(node) && node.constructed)
            out += "DER 要求字符串为原始（primitive）类型，不允许分片"
        return out
    }

    /** Concatenates the primitive content of a (possibly chunked) string node. */
    fun flattenContent(node: Node, data: ByteArray): ByteArray {
        if (!node.constructed) return data.copyOfRange(node.contentOffset, node.contentEnd)
        val out = java.io.ByteArrayOutputStream()
        fun rec(n: Node) {
            if (n.constructed) n.children.forEach(::rec)
            else out.write(data, n.contentOffset, n.contentEnd - n.contentOffset)
        }
        rec(node)
        return out.toByteArray()
    }
}

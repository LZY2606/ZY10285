package prism

import java.time.LocalDateTime
import java.time.ZoneOffset

data class Change(val path: String, val nodeId: Int, val reason: String)

data class NormResult(
    val canonicalHex: String,
    val changes: List<Change>,
    val matchesInput: Boolean,
)

/** [bytes] are the node's canonical content octets; [chunked] marks a CER chunk sequence. */
private data class ContentOut(val bytes: ByteArray, val chunked: Boolean)

object Normalize {

    fun normalize(result: ParseResult, mode: Mode): NormResult {
        if (mode == Mode.BER) {
            return NormResult(result.data.hex(), emptyList(), true)
        }
        val changes = mutableListOf<Change>()
        val out = java.io.ByteArrayOutputStream()
        result.roots.forEachIndexed { i, root ->
            out.write(encodeNode(root, result.data, mode, "$i", changes))
        }
        val bytes = out.toByteArray()
        return NormResult(bytes.hex(), changes, bytes.contentEquals(result.data))
    }

    private fun encodeNode(
        node: Node, data: ByteArray, mode: Mode, path: String,
        changes: MutableList<Change>,
    ): ByteArray {
        // Unknown universal / context-specific / application / private tags are
        // preserved byte-for-byte, children untouched.
        if (!Tags.isKnown(node)) {
            changes += Change(path, node.id, "未知 ${node.tagClass.label} tag ${node.tagNumber}，原样保留")
            return data.copyOfRange(node.headerOffset, node.endOffset)
        }
        val stringLike = node.tagClass == TagClass.UNIVERSAL && Tags.isStringLike(node)
        val content = canonicalContent(node, data, mode, path, changes)
        return when (mode) {
            Mode.DER -> {
                val tag = if (stringLike && node.constructed) primitiveTagOf(node) else node.tagRaw
                if (node.length is Len.Indefinite)
                    changes += Change(path, node.id, "不定长度改为最短定长形式")
                else if (!isShortestLength(node))
                    changes += Change(path, node.id, "长度字段改为最短定长形式")
                tag + encodeLength(content.bytes.size.toLong()) + content.bytes
            }
            Mode.CER -> {
                val constructedOut = if (stringLike) content.chunked else node.constructed
                if (constructedOut) {
                    val tag = if (node.constructed) node.tagRaw else constructedTagOf(node)
                    if (node.length !is Len.Indefinite)
                        changes += Change(path, node.id, "构造类型改为不定长度 + EOC")
                    tag + byteArrayOf(0x80.toByte()) + content.bytes + byteArrayOf(0, 0)
                } else {
                    val tag = if (stringLike && node.constructed) primitiveTagOf(node) else node.tagRaw
                    if (!isShortestLength(node) || node.length is Len.Indefinite)
                        changes += Change(path, node.id, "长度字段改为最短定长形式")
                    tag + encodeLength(content.bytes.size.toLong()) + content.bytes
                }
            }
            Mode.BER -> data.copyOfRange(node.headerOffset, node.endOffset)
        }
    }

    private fun canonicalContent(
        node: Node, data: ByteArray, mode: Mode, path: String,
        changes: MutableList<Change>,
    ): ContentOut {
        // Chunked / constructed string: flatten (DER) or re-chunk at 1000 (CER).
        if (node.tagClass == TagClass.UNIVERSAL && Tags.isStringLike(node)) {
            val flat = Checks.flattenContent(node, data)
            if (mode == Mode.DER) {
                if (node.constructed)
                    changes += Change(path, node.id, "分片字符串合并为原始类型")
                return ContentOut(canonicalPrimitiveValue(node, flat, path, changes), false)
            }
            if (flat.size > 1000) {
                val out = java.io.ByteArrayOutputStream()
                var i = 0
                while (i < flat.size) {
                    val n = minOf(1000, flat.size - i)
                    out.write(primitiveTagOf(node))
                    out.write(encodeLength(n.toLong()))
                    out.write(flat, i, n)
                    i += n
                }
                val chunked = out.toByteArray()
                val original = data.copyOfRange(node.contentOffset, node.contentEnd)
                if (!node.constructed || !chunked.contentEquals(original)) {
                    val last = if (flat.size % 1000 == 0) 1000 else flat.size % 1000
                    changes += Change(path, node.id, "字符串按 CER 分片（每片 1000 字节，最后一片 $last 字节）")
                }
                return ContentOut(chunked, true)
            }
            if (node.constructed)
                changes += Change(path, node.id, "字符串不超过 1000 字节，合并为单个原始分片")
            return ContentOut(canonicalPrimitiveValue(node, flat, path, changes), false)
        }

        if (node.constructed) {
            var kids = node.children.mapIndexed { i, child ->
                encodeNode(child, data, mode, "$path/$i", changes)
            }
            if (node.tagClass == TagClass.UNIVERSAL && node.tagNumber == Tags.SET) {
                // SET / SET OF: sort by the full canonical encoding bytes,
                // never by decoded text. For SET OF (identical tags) this is
                // exactly the DER/CER rule; for SET the tag octets prefix the
                // encoding, so encoding order implies DER tag order.
                val sorted = kids.sortedWith { a, b -> compareBytes(a, b) }
                if (sorted.indices.any { !kids[it].contentEquals(sorted[it]) }) {
                    changes += Change(path, node.id,
                        "SET/SET OF 按完整 ${mode.name} 编码字节序重排（非按解码文本）")
                    kids = sorted
                }
            }
            val out = java.io.ByteArrayOutputStream()
            kids.forEach { out.write(it) }
            return ContentOut(out.toByteArray(), false)
        }

        val raw = data.copyOfRange(node.contentOffset, node.contentEnd)
        return ContentOut(canonicalPrimitiveValue(node, raw, path, changes), false)
    }

    private fun canonicalPrimitiveValue(
        node: Node, c: ByteArray, path: String, changes: MutableList<Change>,
    ): ByteArray {
        if (node.tagClass != TagClass.UNIVERSAL || node.constructed) return c
        when (node.tagNumber) {
            Tags.INTEGER, Tags.ENUMERATED -> {
                if (c.isEmpty()) return c
                var i = 0
                while (i + 1 < c.size) {
                    val b0 = c[i].toInt() and 0xFF
                    val b1 = c[i + 1].toInt() and 0xFF
                    if ((b0 == 0x00 && b1 < 0x80) || (b0 == 0xFF && b1 >= 0x80)) i++ else break
                }
                if (i > 0) {
                    changes += Change(path, node.id, "INTEGER 最小补码：去除 $i 个冗余前导字节")
                    return c.copyOfRange(i, c.size)
                }
            }
            Tags.BOOLEAN -> {
                if (c.size == 1 && c[0].toInt() != 0 && c[0].toInt() != 0xFF) {
                    changes += Change(path, node.id, "BOOLEAN 规范为 0xFF")
                    return byteArrayOf(0xFF.toByte())
                }
            }
            Tags.BIT_STRING -> {
                if (c.size > 1) {
                    val unused = c[0].toInt() and 0xFF
                    if (unused in 1..7) {
                        val mask = (1 shl unused) - 1
                        if (c.last().toInt() and mask != 0) {
                            val fixed = c.copyOf()
                            fixed[fixed.size - 1] = (fixed.last().toInt() and mask.inv()).toByte()
                            changes += Change(path, node.id, "BIT STRING 未用位清零（unused=$unused）")
                            return fixed
                        }
                    }
                }
            }
            Tags.OID -> {
                val fixed = minimalOid(c) ?: return c
                if (!fixed.contentEquals(c)) {
                    changes += Change(path, node.id, "OID 子标识符改为最短 base-128 形式")
                    return fixed
                }
            }
            Tags.UTC_TIME, Tags.GENERALIZED_TIME -> {
                val fixed = canonicalTime(c, node.tagNumber == Tags.UTC_TIME) ?: return c
                if (!fixed.contentEquals(c)) {
                    changes += Change(path, node.id, "时间转换为 UTC（Z 结尾，含秒）")
                    return fixed
                }
            }
        }
        return c
    }

    /** Strips redundant leading 0x80 groups from every base-128 subidentifier. */
    fun minimalOid(c: ByteArray): ByteArray? {
        if (c.isEmpty()) return null
        val out = java.io.ByteArrayOutputStream()
        var i = 0
        while (i < c.size) {
            var start = i
            while (i < c.size && c[i].toInt() and 0x80 != 0) i++
            if (i >= c.size) return null // truncated final subidentifier
            val end = i // inclusive index of the subidentifier's final byte
            while (start < end && c[start].toInt() and 0xFF == 0x80) start++
            for (j in start..end) out.write(c[j].toInt())
            i++
        }
        return out.toByteArray()
    }

    fun canonicalTime(c: ByteArray, utc: Boolean): ByteArray? {
        val s = String(c, Charsets.US_ASCII)
        val re = if (utc)
            Regex("""^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(Z|[+-]\d{4})$""")
        else
            Regex("""^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(Z|[+-]\d{4})$""")
        val m = re.matchEntire(s) ?: return null
        val g = m.groupValues
        val year = if (utc) {
            val yy = g[1].toInt()
            if (yy < 50) 2000 + yy else 1900 + yy
        } else g[1].toInt()
        val sec = if (g[6].isEmpty()) 0 else g[6].toInt()
        val ldt = try {
            LocalDateTime.of(year, g[2].toInt(), g[3].toInt(), g[4].toInt(), g[5].toInt(), sec)
        } catch (e: Exception) {
            return null
        }
        val zone = g.last()
        val instant = if (zone == "Z") ldt.toInstant(ZoneOffset.UTC)
        else {
            val sign = if (zone[0] == '-') -1 else 1
            val off = ZoneOffset.ofTotalSeconds(
                sign * (zone.substring(1, 3).toInt() * 3600 + zone.substring(3, 5).toInt() * 60)
            )
            ldt.toInstant(off)
        }
        val z = instant.atOffset(ZoneOffset.UTC)
        val text = if (utc)
            "%02d%02d%02d%02d%02d%02dZ".format(z.year % 100, z.monthValue, z.dayOfMonth, z.hour, z.minute, z.second)
        else
            "%04d%02d%02d%02d%02d%02dZ".format(z.year, z.monthValue, z.dayOfMonth, z.hour, z.minute, z.second)
        return text.toByteArray(Charsets.US_ASCII)
    }

    private fun primitiveTagOf(node: Node): ByteArray {
        val raw = node.tagRaw.copyOf()
        raw[0] = (raw[0].toInt() and 0xDF).toByte()
        return raw
    }

    private fun constructedTagOf(node: Node): ByteArray {
        val raw = node.tagRaw.copyOf()
        raw[0] = (raw[0].toInt() or 0x20).toByte()
        return raw
    }

    private fun isShortestLength(node: Node): Boolean {
        val len = node.length as? Len.Definite ?: return false
        return encodeLength(len.n).contentEquals(node.lengthRaw)
    }

    fun encodeLength(n: Long): ByteArray {
        require(n >= 0)
        if (n < 128) return byteArrayOf(n.toByte())
        var v = n
        val tmp = mutableListOf<Byte>()
        while (v > 0) { tmp += (v and 0xFF).toByte(); v = v shr 8 }
        return byteArrayOf((0x80 or tmp.size).toByte()) + tmp.reversed().toByteArray()
    }

    fun compareBytes(a: ByteArray, b: ByteArray): Int {
        val n = minOf(a.size, b.size)
        for (i in 0 until n) {
            val d = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (d != 0) return d
        }
        return a.size - b.size
    }
}

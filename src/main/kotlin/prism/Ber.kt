package prism

enum class TagClass(val label: String) {
    UNIVERSAL("universal"),
    APPLICATION("application"),
    CONTEXT("context-specific"),
    PRIVATE("private");

    companion object {
        fun of(bits: Int): TagClass = entries[bits and 3]
    }
}

sealed interface Len {
    data class Definite(val n: Long) : Len
    data object Indefinite : Len
    data object Invalid : Len
}

data class Node(
    val id: Int,
    val depth: Int,
    val tagClass: TagClass,
    val constructed: Boolean,
    val tagNumber: Long,
    val tagRaw: ByteArray,
    val lengthRaw: ByteArray,
    val length: Len,
    val headerOffset: Int,
    val contentOffset: Int,
    val contentEnd: Int,
    val endOffset: Int,
    val children: MutableList<Node> = mutableListOf(),
    val errors: MutableList<String> = mutableListOf(),
    var decoded: String? = null,
) {
    val isEoc: Boolean get() = tagClass == TagClass.UNIVERSAL && tagNumber == 0L && !constructed
}

data class ParseResult(val roots: List<Node>, val data: ByteArray)

object BerParser {
    const val MAX_DEPTH = 64
    private const val MAX_TAG_BYTES = 9
    private const val MAX_LENGTH_BYTES = 8

    fun parse(data: ByteArray): ParseResult {
        val state = State(data)
        val roots = mutableListOf<Node>()
        var off = 0
        while (off < data.size) {
            val next = parseTlv(state, off, data.size, 0, roots)
            check(next > off) { "parser made no progress at $off" }
            off = next
        }
        return ParseResult(roots, data)
    }

    private class State(val data: ByteArray) {
        var nextId = 0
    }

    /**
     * Parses one TLV at [off], bounded by [limit] (exclusive). Always returns an
     * offset strictly greater than [off] so a corrupt node never stalls the loop;
     * the bytes after a bad node remain parseable as recovery evidence.
     */
    private fun parseTlv(state: State, off: Int, limit: Int, depth: Int, sink: MutableList<Node>): Int {
        val data = state.data
        val id = state.nextId++
        if (depth > MAX_DEPTH) {
            sink += Node(id, depth, TagClass.PRIVATE, false, -1, byteArrayOf(), byteArrayOf(),
                Len.Invalid, off, off, off, limit,
                errors = mutableListOf("嵌套深度超过 $MAX_DEPTH，停止展开"))
            return limit
        }

        // ---- tag field ----
        val b0 = data[off].toInt() and 0xFF
        val tagClass = TagClass.of(b0 shr 6)
        val constructed = b0 and 0x20 != 0
        var tagNumber = (b0 and 0x1F).toLong()
        var tagLen = 1
        var tagOverflow = false
        if (b0 and 0x1F == 0x1F) {
            tagNumber = 0
            var more = true
            while (more) {
                if (off + tagLen >= limit) {
                    val raw = data.copyOfRange(off, limit)
                    sink += Node(id, depth, tagClass, constructed, -1, raw, byteArrayOf(),
                        Len.Invalid, off, limit, limit, limit,
                        errors = mutableListOf("高 tag number 形式被截断"))
                    return limit
                }
                if (tagLen > MAX_TAG_BYTES) {
                    tagOverflow = true
                    break
                }
                val b = data[off + tagLen].toInt() and 0xFF
                tagLen++
                if (tagNumber > (Long.MAX_VALUE - (b and 0x7F)) / 128) {
                    tagOverflow = true
                } else if (!tagOverflow) {
                    tagNumber = tagNumber * 128 + (b and 0x7F)
                }
                more = b and 0x80 != 0
            }
        }
        val tagRaw = data.copyOfRange(off, minOf(off + tagLen, limit))
        val errors = mutableListOf<String>()
        if (tagOverflow) errors += "tag number 溢出（超过 64 位），已截断读取"

        // EOC: universal primitive tag 0. Only legal as the terminator of an
        // indefinite-length constructed node; the caller consumes those. Anything
        // reaching here is an orphan.
        if (tagClass == TagClass.UNIVERSAL && tagNumber == 0L && !constructed) {
            val hasZeroLen = off + 1 < limit && data[off + 1].toInt() == 0
            val end = if (hasZeroLen) off + 2 else off + 1
            sink += Node(id, depth, tagClass, false, 0, tagRaw,
                if (hasZeroLen) byteArrayOf(0) else byteArrayOf(),
                if (hasZeroLen) Len.Definite(0) else Len.Invalid,
                off, end, end, end,
                errors = mutableListOf("孤立 EOC：没有对应的不定长度构造节点"))
            return end
        }

        // ---- length field ----
        val lenOff = off + tagLen
        if (lenOff >= limit) {
            sink += Node(id, depth, tagClass, constructed, tagNumber, tagRaw, byteArrayOf(),
                Len.Invalid, off, limit, limit, limit,
                errors = (errors + "长度字段缺失").toMutableList())
            return limit
        }
        val lb = data[lenOff].toInt() and 0xFF
        var length: Len
        var lengthRaw: ByteArray
        var contentOffset: Int
        var contentEnd: Int
        var endOffset: Int
        val children = mutableListOf<Node>()

        when {
            lb < 0x80 -> {
                length = Len.Definite(lb.toLong())
                lengthRaw = data.copyOfRange(lenOff, lenOff + 1)
                contentOffset = lenOff + 1
                contentEnd = clampAdd(contentOffset, lb.toLong(), limit, errors)
                endOffset = contentEnd
            }
            lb == 0x80 -> {
                length = Len.Indefinite
                lengthRaw = data.copyOfRange(lenOff, lenOff + 1)
                contentOffset = lenOff + 1
                if (!constructed) errors += "原始（primitive）类型不允许不定长度"
                // Parse children until the EOC belonging to THIS level. Nested
                // indefinite nodes consume their own EOC inside the recursion.
                var cur = contentOffset
                var closed = false
                while (cur < limit) {
                    if (cur + 1 < limit && data[cur].toInt() == 0 && data[cur + 1].toInt() == 0) {
                        cur += 2
                        closed = true
                        break
                    }
                    cur = parseTlv(state, cur, limit, depth + 1, children)
                }
                if (!closed) errors += "不定长度缺少匹配的 EOC（00 00）"
                contentEnd = if (closed) cur - 2 else cur
                endOffset = cur
                sink += Node(id, depth, tagClass, constructed, tagNumber, tagRaw, lengthRaw,
                    length, off, contentOffset, contentEnd, endOffset, children,
                    errors)
                return endOffset
            }
            lb == 0xFF -> {
                // Reserved in every BER flavour. Consume tag + this byte and let
                // the following bytes be parsed as fresh TLVs (recovery evidence).
                sink += Node(id, depth, tagClass, constructed, tagNumber, tagRaw,
                    data.copyOfRange(lenOff, lenOff + 1), Len.Invalid,
                    off, lenOff + 1, lenOff + 1, lenOff + 1,
                    errors = (errors + "长度字节 0xFF 为保留值，无法定位内容边界").toMutableList())
                return lenOff + 1
            }
            else -> {
                val k = lb and 0x7F
                val avail = limit - (lenOff + 1)
                if (k > MAX_LENGTH_BYTES) {
                    val take = minOf(k, avail)
                    sink += Node(id, depth, tagClass, constructed, tagNumber, tagRaw,
                        data.copyOfRange(lenOff, lenOff + 1 + take), Len.Invalid,
                        off, lenOff + 1 + take, lenOff + 1 + take, lenOff + 1 + take,
                        errors = (errors + "长度字段 $k 字节，超过 8 字节上限（溢出保护）").toMutableList())
                    return lenOff + 1 + take
                }
                if (avail < k) {
                    sink += Node(id, depth, tagClass, constructed, tagNumber, tagRaw,
                        data.copyOfRange(lenOff, limit), Len.Invalid,
                        off, limit, limit, limit,
                        errors = (errors + "长度字段被截断：需要 $k 字节，仅剩 $avail").toMutableList())
                    return limit
                }
                var n = 0L
                for (i in 0 until k) {
                    n = n * 256 + (data[lenOff + 1 + i].toInt() and 0xFF)
                    if (n < 0) { // 8-byte length with top bit set overflows Long
                        n = Long.MAX_VALUE
                        errors += "长度值溢出（超过 63 位），按截断处理"
                        break
                    }
                }
                length = Len.Definite(n)
                lengthRaw = data.copyOfRange(lenOff, lenOff + 1 + k)
                contentOffset = lenOff + 1 + k
                contentEnd = clampAdd(contentOffset, n, limit, errors)
                endOffset = contentEnd
            }
        }

        if (constructed) {
            var cur = contentOffset
            while (cur < contentEnd) {
                cur = parseTlv(state, cur, contentEnd, depth + 1, children)
            }
        }
        sink += Node(id, depth, tagClass, constructed, tagNumber, tagRaw, lengthRaw,
            length, off, contentOffset, contentEnd, endOffset, children, errors)
        return endOffset
    }

    private fun clampAdd(start: Int, n: Long, limit: Int, errors: MutableList<String>): Int {
        val end = start.toLong() + n
        return if (end < start || end > limit) {
            errors += "内容长度 $n 超出可用字节（仅剩 ${limit - start}），已按截断处理"
            limit
        } else {
            end.toInt()
        }
    }

}

fun ByteArray.hex(): String = joinToString("") { "%02X".format(it) }

fun String.hexToBytes(): ByteArray {
    val clean = filter { it.isDigit() || it.lowercaseChar() in 'a'..'f' }
    require(clean.length % 2 == 0) { "hex 长度必须为偶数" }
    return ByteArray(clean.length / 2) { clean.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}

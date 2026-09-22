package prism

/** Minimal JSON model + renderer — no external dependencies. */
sealed interface JVal {
    data class Str(val s: String) : JVal
    data class Num(val n: Number) : JVal
    data class Bool(val b: Boolean) : JVal
    data class Arr(val items: List<JVal>) : JVal
    data class Obj(val fields: List<Pair<String, JVal>>) : JVal
}

object Json {
    fun render(v: JVal): String = StringBuilder().also { write(it, v) }.toString()

    private fun write(sb: StringBuilder, v: JVal) {
        when (v) {
            is JVal.Str -> writeString(sb, v.s)
            is JVal.Num -> sb.append(v.n)
            is JVal.Bool -> sb.append(v.b)
            is JVal.Arr -> {
                sb.append('[')
                v.items.forEachIndexed { i, item ->
                    if (i > 0) sb.append(',')
                    write(sb, item)
                }
                sb.append(']')
            }
            is JVal.Obj -> {
                sb.append('{')
                v.fields.forEachIndexed { i, (k, fv) ->
                    if (i > 0) sb.append(',')
                    writeString(sb, k)
                    sb.append(':')
                    write(sb, fv)
                }
                sb.append('}')
            }
        }
    }

    private fun writeString(sb: StringBuilder, s: String) {
        sb.append('"')
        for (ch in s) when (ch) {
            '"' -> sb.append("\\\"")
            '\\' -> sb.append("\\\\")
            '\n' -> sb.append("\\n")
            '\r' -> sb.append("\\r")
            '\t' -> sb.append("\\t")
            else -> if (ch < ' ') sb.append("\\u%04x".format(ch.code)) else sb.append(ch)
        }
        sb.append('"')
    }
}

fun objOf(vararg fields: Pair<String, JVal?>): JVal.Obj =
    JVal.Obj(fields.filter { it.second != null }.map { it.first to it.second!! })

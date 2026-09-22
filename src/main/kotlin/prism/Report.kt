package prism

object Report {
    fun build(result: ParseResult, mode: Mode, name: String?): String {
        fun attach(n: Node) {
            n.decoded = Decoders.decode(n, result.data)
            n.children.forEach(::attach)
        }
        result.roots.forEach(::attach)

        val findings = Checks.run(result, mode)
        val norm = Normalize.normalize(result, mode)

        return Json.render(objOf(
            "mode" to JVal.Str(mode.name),
            "modeLabel" to JVal.Str(mode.label),
            "name" to name?.let { JVal.Str(it) },
            "inputLength" to JVal.Num(result.data.size),
            "canonicalHex" to JVal.Str(norm.canonicalHex),
            "matchesInput" to JVal.Bool(norm.matchesInput),
            "tree" to JVal.Arr(result.roots.map(::nodeJson)),
            "findings" to JVal.Arr(findings.map { f ->
                objOf(
                    "nodeId" to JVal.Num(f.nodeId),
                    "path" to JVal.Str(f.path),
                    "level" to JVal.Str(f.level),
                    "message" to JVal.Str(f.message),
                )
            }),
            "changes" to JVal.Arr(norm.changes.map { c ->
                objOf(
                    "nodeId" to JVal.Num(c.nodeId),
                    "path" to JVal.Str(c.path),
                    "reason" to JVal.Str(c.reason),
                )
            }),
        ))
    }

    private fun nodeJson(n: Node): JVal = objOf(
        "id" to JVal.Num(n.id),
        "depth" to JVal.Num(n.depth),
        "offset" to JVal.Num(n.headerOffset),
        "tagClass" to JVal.Str(n.tagClass.label),
        "constructed" to JVal.Bool(n.constructed),
        "tagNumber" to JVal.Num(n.tagNumber),
        "tagName" to JVal.Str(Tags.nameOf(n)),
        "tagHex" to JVal.Str(n.tagRaw.hex()),
        "lengthHex" to JVal.Str(n.lengthRaw.hex()),
        "lengthDesc" to JVal.Str(when (val l = n.length) {
            is Len.Definite -> "definite ${l.n}"
            Len.Indefinite -> "indefinite"
            Len.Invalid -> "invalid"
        }),
        "contentStart" to JVal.Num(n.contentOffset),
        "contentEnd" to JVal.Num(n.contentEnd),
        "endOffset" to JVal.Num(n.endOffset),
        "decoded" to n.decoded?.let { JVal.Str(it) },
        "errors" to JVal.Arr(n.errors.map { JVal.Str(it) }),
        "children" to JVal.Arr(n.children.map(::nodeJson)),
    )
}

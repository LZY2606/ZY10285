package prism

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class PrismTest {

    private fun parse(hex: String) = BerParser.parse(hex.hexToBytes())
    private fun norm(hex: String, mode: Mode) = Normalize.normalize(parse(hex), mode)

    // ---------- 范围树 ----------

    @Test
    fun `nested indefinite range tree`() {
        val r = parse("3080308002010500000000")
        assertEquals(1, r.roots.size)
        val outer = r.roots[0]
        assertEquals(TagClass.UNIVERSAL, outer.tagClass)
        assertTrue(outer.constructed)
        assertEquals(16, outer.tagNumber)
        assertEquals(Len.Indefinite, outer.length)
        assertEquals(0, outer.headerOffset)
        assertEquals(2, outer.contentOffset)
        assertEquals(9, outer.contentEnd)   // EOC 不计入内容
        assertEquals(11, outer.endOffset)
        assertTrue(outer.errors.isEmpty())

        assertEquals(1, outer.children.size)
        val inner = outer.children[0]
        assertEquals(2, inner.headerOffset)
        assertEquals(4, inner.contentOffset)
        assertEquals(7, inner.contentEnd)
        assertEquals(9, inner.endOffset)    // 内层 EOC 只关闭内层
        assertEquals(Len.Indefinite, inner.length)

        assertEquals(1, inner.children.size)
        val intNode = inner.children[0]
        assertEquals(2, intNode.tagNumber)
        assertFalse(intNode.constructed)
        assertEquals(4, intNode.headerOffset)
        assertEquals(6, intNode.contentOffset)
        assertEquals(7, intNode.contentEnd)
        assertEquals(7, intNode.endOffset)
    }

    @Test
    fun `high tag number long form`() {
        val r = parse("BF2103020105")
        val n = r.roots.single()
        assertEquals(TagClass.CONTEXT, n.tagClass)
        assertTrue(n.constructed)
        assertEquals(33, n.tagNumber)
        assertEquals("BF21", n.tagRaw.hex())
        assertEquals(1, n.children.size)
        assertEquals(2, n.children[0].tagNumber)
    }

    // ---------- 规范化幂等 ----------

    @Test
    fun `normalization is idempotent for all fixtures`() {
        for (f in Fixtures.all) {
            for (mode in listOf(Mode.CER, Mode.DER)) {
                val first = norm(f.hex, mode)
                val second = norm(first.canonicalHex, mode)
                assertEquals(
                    first.canonicalHex, second.canonicalHex,
                    "fixture ${f.id} / $mode 不幂等",
                )
            }
        }
    }

    // ---------- CER 分片界限 ----------

    @Test
    fun `CER chunks string at 1000 byte bounds`() {
        val content = ByteArray(2500) { (it % 251).toByte() }
        val input = byteArrayOf(0x04, 0x82.toByte(), 0x09, 0xC4.toByte()) + content
        val n = Normalize.normalize(BerParser.parse(input), Mode.CER)
        val reparsed = BerParser.parse(n.canonicalHex.hexToBytes())
        val root = reparsed.roots.single()
        assertTrue(root.constructed, "CER 长字符串应为构造类型")
        assertEquals(Len.Indefinite, root.length)
        assertEquals(4, root.tagNumber)
        assertEquals(listOf(1000, 1000, 500), root.children.map { it.contentEnd - it.contentOffset })
        root.children.dropLast(1).forEach {
            assertEquals(1000, it.contentEnd - it.contentOffset, "除最后一片外必须为 1000 字节")
            assertFalse(it.constructed, "分片必须是原始类型")
        }
        // 幂等
        val again = Normalize.normalize(reparsed, Mode.CER)
        assertEquals(n.canonicalHex, again.canonicalHex)
    }

    @Test
    fun `CER flags bad chunk boundary`() {
        // 构造 OCTET STRING：两片 900 + 900，违反"除最后一片外必须 1000"
        val hex = "2480" + "04820384" + "AA".repeat(900) + "04820384" + "BB".repeat(900) + "0000"
        val findings = Checks.run(parse(hex), Mode.CER)
        assertTrue(findings.any { it.message.contains("CER 分片界限") }, "应报告分片界限违规: $findings")
    }

    // ---------- 坏节点之后的可恢复证据 ----------

    @Test
    fun `reserved length byte leaves recoverable evidence`() {
        val r = parse("02FF020107")
        assertEquals(2, r.roots.size, "坏节点之后仍应解析出兄弟节点")
        val bad = r.roots[0]
        assertTrue(bad.errors.any { it.contains("0xFF") })
        assertEquals(Len.Invalid, bad.length)
        val good = r.roots[1]
        assertEquals(2, good.tagNumber)
        assertEquals(2, good.headerOffset)
        assertTrue(good.errors.isEmpty())
        assertEquals("7", Decoders.decode(good, r.data))
    }

    @Test
    fun `orphan EOC is reported and parsing continues`() {
        val r = parse("0000020107")
        assertEquals(2, r.roots.size)
        assertTrue(r.roots[0].isEoc)
        assertTrue(r.roots[0].errors.any { it.contains("孤立 EOC") })
        assertEquals("7", Decoders.decode(r.roots[1], r.data))
    }

    @Test
    fun `truncated content is clamped with evidence`() {
        // SEQUENCE 声明 10 字节内容，实际只有 3
        val r = parse("300A020105")
        val root = r.roots.single()
        assertTrue(root.errors.any { it.contains("超出可用字节") })
        assertEquals(5, root.contentEnd)
        assertEquals(1, root.children.size)
        assertEquals(2, root.children[0].tagNumber)
    }

    // ---------- DER 规则 ----------

    @Test
    fun `DER sorts SET OF by full encoding not decoded text`() {
        val n = norm("3109040341424104024142", Mode.DER)
        assertEquals("3109040241420403414241", n.canonicalHex)
        assertTrue(n.changes.any { it.reason.contains("编码字节序重排") })
        assertFalse(n.matchesInput)
    }

    @Test
    fun `INTEGER minimal twos complement`() {
        val findings = Checks.run(parse("0202007F"), Mode.DER)
        assertTrue(findings.any { it.message.contains("非最小补码") })
        assertEquals("02017F", norm("0202007F", Mode.DER).canonicalHex)
        // 负数同样处理：FF FF 01 -> FF 01
        assertEquals("0202FF01", norm("0203FFFF01", Mode.DER).canonicalHex)
    }

    @Test
    fun `BIT STRING unused bits must be zero`() {
        val findings = Checks.run(parse("0302046F"), Mode.DER)
        assertTrue(findings.any { it.message.contains("未用位") })
        assertEquals("03020460", norm("0302046F", Mode.DER).canonicalHex)
    }

    @Test
    fun `OID shortest base-128`() {
        val findings = Checks.run(parse("060455048003"), Mode.DER)
        assertTrue(findings.any { it.message.contains("最短 base-128") }, "findings=$findings")
        assertEquals("0603550403", norm("060455048003", Mode.DER).canonicalHex)
    }

    @Test
    fun `time zone converted to Z`() {
        val findings = Checks.run(parse("17113236303932333132303030302B30383030"), Mode.DER)
        assertTrue(findings.any { it.message.contains("UTC") }, "findings=$findings")
        assertEquals("170D3236303932333034303030305A",
            norm("17113236303932333132303030302B30383030", Mode.DER).canonicalHex)
    }

    @Test
    fun `DER forbids indefinite and constructed strings`() {
        val findings = Checks.run(parse("2480040568656C6C6F0405776F726C640000"), Mode.DER)
        assertTrue(findings.any { it.message.contains("不定长度") })
        assertTrue(findings.any { it.message.contains("原始") })
        assertEquals("040A68656C6C6F776F726C64",
            norm("2480040568656C6C6F0405776F726C640000", Mode.DER).canonicalHex)
    }

    @Test
    fun `unknown tags preserved as-is`() {
        val n = norm("BF2103020105", Mode.DER)
        assertEquals("BF2103020105", n.canonicalHex)
        assertTrue(n.changes.any { it.reason.contains("原样保留") })
    }

    // ---------- 溢出保护 ----------

    @Test
    fun `length overflow protection`() {
        // 8 字节长度，最高位置位 -> 超过 63 位
        val r = parse("3088FFFFFFFFFFFFFFFF" + "00".repeat(4))
        assertTrue(r.roots.single().errors.any { it.contains("溢出") || it.contains("超出可用字节") })
        // 长度字段声明 9 字节 -> 超过上限
        val r2 = parse("3089010203040506070809")
        assertTrue(r2.roots.single().errors.any { it.contains("溢出保护") })
    }

    @Test
    fun `deep nesting is bounded`() {
        val hex = "3081FF".repeat(0).ifEmpty { "" }
        val sb = StringBuilder()
        repeat(200) { sb.append("3081C8") } // 每层声明 200 字节内容
        val r = parse(sb.toString() + hex)
        assertTrue(true) // 不崩溃、不栈溢出即为通过
        assertTrue(r.roots.isNotEmpty())
    }

    // ---------- SQLite 迁移与读写 ----------

    @Test
    fun `sqlite migrations and roundtrip`(@TempDir dir: Path) {
        val dbFile = dir.resolve("test.db").toString()
        Db.init(dbFile)
        try {
            val result = parse("020105")
            val report = Report.build(result, Mode.DER, "t")
            val id = Db.insertImport("t", Mode.DER, "020105", "020105", report)
            assertTrue(id > 0)
            val list = Db.listImports()
            assertEquals(1, list.size)
            assertEquals("t", list[0].name)
            assertEquals(report, Db.getReport(id))
            // 重复 init 应跳过已应用的迁移
            Db.init(dbFile)
            assertEquals(1, Db.listImports().size)
        } finally {
            Db.close()
        }
    }

    // ---------- 报告 JSON ----------

    @Test
    fun `report contains tree findings and changes`() {
        val report = Report.build(parse("3109040341424104024142"), Mode.DER, "demo")
        assertTrue(report.contains("\"tree\""))
        assertTrue(report.contains("\"findings\""))
        assertTrue(report.contains("\"changes\""))
        assertTrue(report.contains("重排"))
        assertTrue(report.contains("\"tagClass\":\"universal\""))
        assertTrue(report.contains("\"constructed\":true"))
    }
}

package prism

data class Fixture(val id: String, val title: String, val description: String, val hex: String)

object Fixtures {
    val all: List<Fixture> = listOf(
        Fixture(
            "high-tag",
            "高 tag number（长形式 tag）",
            "context-specific 构造 tag 33（BF 21），内嵌 INTEGER 5",
            "BF2103020105",
        ),
        Fixture(
            "nested-indefinite",
            "嵌套不定长度",
            "两层 indefinite SEQUENCE，EOC 只关闭当前层",
            "3080308002010500000000",
        ),
        Fixture(
            "non-minimal-integer",
            "非最短 INTEGER",
            "INTEGER 内容 00 7F，前导 0x00 冗余（DER/CER 违规）",
            "0202007F",
        ),
        Fixture(
            "setof-prefix-collision",
            "SET OF 排序碰撞前缀",
            "两个 OCTET STRING 共享前缀 AB/ABA，输入顺序错误，须按完整 DER 编码排序",
            "3109040341424104024142",
        ),
        Fixture(
            "chunked-string",
            "分片字符串（构造 OCTET STRING）",
            "不定长度构造 OCTET STRING，两个原始分片 'hello' 'world'",
            "2480040568656C6C6F0405776F726C640000",
        ),
        Fixture(
            "orphan-eoc",
            "孤立 EOC 后可恢复",
            "开头是孤立 EOC（00 00），其后 INTEGER 7 仍可解析为恢复证据",
            "0000020107",
        ),
        Fixture(
            "reserved-length",
            "保留长度字节 0xFF 后可恢复",
            "INTEGER 的长度字节为保留值 0xFF，边界未知；后续 INTEGER 7 仍被解析",
            "02FF020107",
        ),
        Fixture(
            "time-with-zone",
            "带时区的 UTCTime",
            "UTCTime 260923120000+0800，DER/CER 要求转换为 Z 形式",
            "17113236303932333132303030302B30383030",
        ),
        Fixture(
            "bitstring-unused",
            "BIT STRING 未用位未清零",
            "unused=4 但末字节低 4 位非零（0x6F）",
            "0302046F",
        ),
        Fixture(
            "oid-nonminimal",
            "OID 非最短 base-128",
            "OID 2.5.4.3 的最后一个子标识符写成冗余的 80 03",
            "060455048003",
        ),
    )

    fun byId(id: String): Fixture? = all.firstOrNull { it.id == id }
}

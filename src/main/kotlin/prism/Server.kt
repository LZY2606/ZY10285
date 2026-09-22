package prism

import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing

fun main(args: Array<String>) {
    var port = 5985
    var dbPath = "prism.db"
    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--port" -> port = args.getOrElse(i + 1) { "5985" }.toInt().also { i++ }
            "--db" -> dbPath = args.getOrElse(i + 1) { "prism.db" }.also { i++ }
        }
        i++
    }
    Db.init(dbPath)
    println("规约棱镜 listening on http://127.0.0.1:$port (db: $dbPath)")
    embeddedServer(Netty, port = port, host = "127.0.0.1") { prismModule() }.start(wait = true)
}

fun Application.prismModule() {
    val indexHtml = object {}.javaClass.getResource("/web/index.html")!!.readText()

    routing {
        get("/") {
            call.respondText(indexHtml, ContentType.Text.Html)
        }
        get("/api/fixtures") {
            call.respondText(Json.render(JVal.Arr(Fixtures.all.map { f ->
                objOf(
                    "id" to JVal.Str(f.id),
                    "title" to JVal.Str(f.title),
                    "description" to JVal.Str(f.description),
                    "hex" to JVal.Str(f.hex),
                )
            })), ContentType.Application.Json)
        }
        post("/api/parse") {
          try {
            val params = call.receiveParameters()
            val mode = Mode.of(params["mode"])
            val name = params["name"]?.ifBlank { null }
            val hex = params["hex"] ?: ""
            val bytes = try {
                hex.hexToBytes()
            } catch (e: Exception) {
                return@post call.respondText(
                    Json.render(objOf("error" to JVal.Str("hex 解析失败：${e.message}"))),
                    ContentType.Application.Json, HttpStatusCode.BadRequest,
                )
            }
            if (bytes.isEmpty()) {
                return@post call.respondText(
                    Json.render(objOf("error" to JVal.Str("输入为空"))),
                    ContentType.Application.Json, HttpStatusCode.BadRequest,
                )
            }
            val result = BerParser.parse(bytes)
            val report = Report.build(result, mode, name)
            val normHex = if (mode == Mode.BER) bytes.hex()
                else Normalize.normalize(result, mode).canonicalHex
            val id = Db.insertImport(name, mode, bytes.hex(), normHex, report)
            call.respondText(
                report.trimEnd('}') + ",\"importId\":$id}",
                ContentType.Application.Json,
            )
          } catch (e: Exception) {
            call.respondText(
                Json.render(objOf("error" to JVal.Str(e.message ?: e.javaClass.simpleName))),
                ContentType.Application.Json, HttpStatusCode.BadRequest,
            )
          }
        }
        get("/api/history") {
            call.respondText(Json.render(JVal.Arr(Db.listImports().map { r ->
                objOf(
                    "id" to JVal.Num(r.id),
                    "createdAt" to JVal.Str(r.createdAt),
                    "name" to r.name?.let { JVal.Str(it) },
                    "mode" to JVal.Str(r.mode),
                    "inputLength" to JVal.Num(r.inputHex.length / 2),
                )
            })), ContentType.Application.Json)
        }
        get("/api/imports/{id}") {
            val id = call.parameters["id"]?.toLongOrNull()
            val report = id?.let { Db.getReport(it) }
            if (report == null) {
                call.respondText(
                    Json.render(objOf("error" to JVal.Str("未找到该导入记录"))),
                    ContentType.Application.Json, HttpStatusCode.NotFound,
                )
            } else {
                call.respondText(report, ContentType.Application.Json)
            }
        }
    }
}

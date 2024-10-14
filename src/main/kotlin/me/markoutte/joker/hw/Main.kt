package me.markoutte.joker.hw

import me.markoutte.joker.helpers.ComputeClassWriter
import org.apache.commons.cli.DefaultParser
import org.apache.commons.cli.Options
import org.objectweb.asm.*
import java.io.File
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method
import java.net.URLClassLoader
import java.nio.ByteBuffer
import java.nio.charset.Charset
import java.nio.file.Files
import java.nio.file.Paths
import java.nio.file.StandardOpenOption
import java.util.concurrent.TimeUnit
import kotlin.io.path.writeBytes
import kotlin.random.Random

@ExperimentalStdlibApi
fun main(args: Array<String>) {
    val options = Options().apply {
        addOption("c", "class", true, "Java class fully qualified name")
        addOption("m", "method", true, "Method to be tested")
        addOption("cp", "classpath", true, "Classpath with libraries")
        addOption("t", "timeout", true, "Maximum time for fuzzing in seconds")
        addOption("s", "seed", true, "The source of randomness")
    }
    val parser = DefaultParser().parse(options, args)
    val className = parser.getOptionValue("class")
    val methodName = parser.getOptionValue("method")
    val classPath = parser.getOptionValue("classpath")
    val timeout = parser.getOptionValue("timeout")?.toLong() ?: 20L
    val seed = parser.getOptionValue("seed")?.toInt() ?: Random.nextInt()
    val random = Random(seed)

    println("Running: $className.$methodName) with seed = $seed")
    val errors = mutableSetOf<String>()
    val b = ByteArray(500)
    val start = System.nanoTime()

    val javaMethod = try {
        loadJavaMethod(className, methodName, classPath)
    } catch (t: Throwable) {
        println("Method $className#$methodName is not found")
        return
    }

    val seeds = mutableMapOf<Int, ByteArray>(
        1 to "<html><body><h1>Test</h1></body></html>".asByteArray(b.size)!!,
        2 to "<!DOCTYPE html><html><head><title>Test</title></head><body></body></html>".asByteArray(b.size)!!,
        3 to "<html><body><div>Unclosed tag".asByteArray(b.size)!!
    )


    while(System.nanoTime() - start < TimeUnit.SECONDS.toNanos(timeout)) {
        val buffer = seeds.values.randomOrNull(random)?.let {
//            logMutation(it, "Random seed mutation")
            random.mutateHtml(it)
        } ?: run {
//            logMutation(b, "Fresh random mutation")
            b.apply(random::nextBytes)
        }

        val inputValues = generateInputValues(javaMethod, buffer)
//        val inputValues = generateHtmlInputValues(javaMethod, buffer)
        val inputValuesString = "${javaMethod.name}: ${inputValues.contentDeepToString()}"
        try {
            ExecutionPath.id = 0
            javaMethod.invoke(null, *inputValues).apply {
                val seedId = ExecutionPath.id
                if (seeds.putIfAbsent(seedId, buffer) == null) {
                    println("New seed added: ${seedId.toHexString()}")
                }
            }
        } catch (e: InvocationTargetException) {
            if (errors.add(e.targetException::class.qualifiedName!!)) {
                val errorName = e.targetException::class.simpleName
                println("New error found: $errorName")
                val path = Paths.get("report$errorName.txt")
                Files.write(path, listOf(
                    "${e.targetException.stackTraceToString()}\n",
                    "$inputValuesString\n",
                    "${buffer.contentToString()}\n",
                ))
                Files.write(path, buffer, StandardOpenOption.APPEND)
                println("Saved to: ${path.fileName}")
            }
        }
    }

    println("Seeds found: ${seeds.size}")
    println("Errors found: ${errors.size}")
    println("Time elapsed: ${TimeUnit.NANOSECONDS.toMillis(
        System.nanoTime() - start
    )} ms")
}

fun loadJavaMethod(className: String, methodName: String, classPath: String): Method {
    val libraries = classPath
        .split(File.pathSeparatorChar)
        .map { File(it).toURI().toURL() }
        .toTypedArray()
    val classLoader = object : URLClassLoader(libraries) {
        override fun loadClass(name: String, resolve: Boolean): Class<*> {
            return if (name.startsWith(className.substringBeforeLast('.'))) {
                transformAndGetClass(name).apply {
                    if (resolve) resolveClass(this)
                }
            } else {
                super.loadClass(name, resolve)
            }
        }

        fun transformAndGetClass(name: String): Class<*> {
            val owner = name.replace('.', '/')
            var bytes =
                getResourceAsStream("$owner.class")!!.use { it.readBytes() }
            val reader = ClassReader(bytes)
            val cl = this
            val writer = ComputeClassWriter(
                reader, ClassWriter.COMPUTE_MAXS or ClassWriter.COMPUTE_FRAMES, cl
            )
            val transformer = object : ClassVisitor(Opcodes.ASM9, writer) {
                override fun visitMethod(
                    access: Int,
                    name: String?,
                    descriptor: String?,
                    signature: String?,
                    exceptions: Array<out String>?
                ): MethodVisitor {
                    return object : MethodVisitor(
                        Opcodes.ASM9,
                        super.visitMethod(
                            access, name, descriptor, signature, exceptions
                        )
                    ) {
                        val ownerName =
                            ExecutionPath.javaClass.canonicalName.replace('.', '/')
                        val fieldName = "id"

                        override fun visitLineNumber(line: Int, start: Label?) {
                            visitFieldInsn(
                                Opcodes.GETSTATIC, ownerName, fieldName, "I"
                            )
                            visitLdcInsn(line)
                            visitInsn(Opcodes.IADD)
                            visitFieldInsn(
                                Opcodes.PUTSTATIC, ownerName, fieldName, "I"
                            )
                            super.visitLineNumber(line, start)
                        }
                    }
                }
            }
            reader.accept(transformer, ClassReader.SKIP_FRAMES)
            bytes = writer.toByteArray().also {
                if (name == className) {
                    Paths.get("Instrumented.class").writeBytes(it)
                }
            }
            return defineClass(name, bytes, 0, bytes.size)
        }
    }
    val javaClass = classLoader.loadClass(className)
    val javaMethod = javaClass.declaredMethods.first {
        "${it.name}(${it.parameterTypes.joinToString(",") {
                c -> c.typeName
        }})" == methodName
    }
    return javaMethod
}

object ExecutionPath {
    @JvmField
    var id: Int = 0
}

fun Random.mutate(buffer: ByteArray): ByteArray {
    val mutated = buffer.clone()
    when (nextInt(0, 2)) { // Different mutation types
        0 -> mutated.changeBytes(this)
        1 -> mutateHtml(buffer)
    }
    return mutated
}

fun ByteArray.changeBytes(random: Random): ByteArray = this.clone().apply {
    val position = random.nextInt(0, size)
    val repeat = random.nextInt((size - position))
    val from = random.nextInt(-128, 127)
    val until = random.nextInt(from + 1, 128)
    repeat(repeat) { i ->
        set(position + i, random.nextInt(from, until).toByte())
    }
}

fun Any.asByteArray(length: Int): ByteArray? = when (this) {
    is String -> {
        val bytes = toByteArray(Charset.forName("koi8"))
        ByteArray(length) {
            if (it == 0) {
                (bytes.size - 1).toUByte().toByte()
            } else if (it - 1 < bytes.size) {
                bytes[it - 1]
            } else {
                0
            }
        }
    }
    else -> null
}

fun generateRandomHTMLString(buffer: ByteBuffer): String {
    val tags = listOf("div", "p", "span", "a", "h1", "h2", "h3")
    val possibleChars = "abcdefghijklmnopqrstuvwxyz0123456789"
    val length = buffer.get().toUByte().toInt() % 100 // Limit string size to prevent too-long inputs
    val sb = StringBuilder()

    repeat(length) {
        when (buffer.get().toUByte().toInt() % 3) {
            0 -> sb.append("<${tags.random(buffer.asRandom())}>") // Opening tag
            1 -> sb.append("</${tags.random(buffer.asRandom())}>") // Closing tag
            2 -> sb.append(possibleChars.random(buffer.asRandom())) // Random text content
        }
    }

    return sb.toString()
}

fun ByteBuffer.asRandom(): Random {
    return Random(this.get().toUByte().toInt())
}

fun generateInputValues(method: Method, data: ByteArray): Array<Any> {
    val buffer = ByteBuffer.wrap(data)
    val parameterTypes = method.parameterTypes
    return Array(parameterTypes.size) { idx ->
        when (parameterTypes[idx]) {
            Int::class.java -> buffer.get().toInt()
            IntArray::class.java -> IntArray(buffer.get().toUByte().toInt()) {
                buffer.get().toInt()
            }
            String::class.java -> generateRandomHTMLString(buffer)
            // Add more types as needed, e.g., lists of tags, nested structures, etc.
            else -> error("Cannot create value of type ${parameterTypes[idx]}")
        }
    }
}

fun logMutation(buffer: ByteArray, mutationType: String) {
    println("Mutation applied: $mutationType on buffer of size ${buffer.size}")
}

fun Random.mutateHtml(buffer: ByteArray): ByteArray {
    val htmlString = String(buffer, Charset.forName("koi8"))
    val position = nextInt(0, htmlString.length)
    val mutationType = nextInt(3)

    val newHtmlString = when (mutationType) {
        0 -> {
            val tag = listOf("<div>", "<span>", "<p>", "<a>", "</div>", "</span>", "</p>", "</a>")
                .random(this)
            htmlString.substring(0, position) + tag + htmlString.substring(position)
        }
        1 -> {
            val attr = listOf("id=\"test\"", "class=\"example\"", "style=\"color:red;\"").random(this)
            val insertPosition = htmlString.indexOf('>', position)
            if (insertPosition != -1) {
                htmlString.substring(0, insertPosition) + " " + attr + htmlString.substring(insertPosition)
            } else {
                htmlString
            }
        }
        2 -> {
            val withAmp = listOf("&lt;", "&gt;", "&amp;")
            htmlString.substring(0, position) + withAmp + htmlString.substring(position)
        }
        else -> htmlString
    }

    return newHtmlString.toByteArray(Charset.forName("koi8"))
}
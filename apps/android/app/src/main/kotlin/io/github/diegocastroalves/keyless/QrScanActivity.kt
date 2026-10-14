package io.github.diegocastroalves.keyless

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.graphics.SurfaceTexture
import android.graphics.pdf.PdfRenderer
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.camera2.CaptureRequest
import android.graphics.ImageFormat
import android.media.ImageReader
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.view.Gravity
import android.view.Surface
import android.view.TextureView
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.FrameLayout
import android.widget.LinearLayout
import org.json.JSONArray
import org.json.JSONObject
import kotlin.concurrent.thread

/**
 * "Scan QR code": a one-time password setup (`otpauth://`) or a Keyless
 * setup code, from the camera or from an image or PDF (an Emergency Kit).
 * Frames are read in memory and decoded by the Rust core; nothing is kept.
 * Answers RESULT_OK with the code's content in `EXTRA_CONTENT`.
 */
class QrScanActivity : Activity() {
    companion object {
        const val EXTRA_WANTED = "wanted"
        const val EXTRA_CONTENT = "content"
        const val WANT_TOTP = "totp"
        const val WANT_SETUP = "setup"
        private const val ASK_CAMERA = 1
        private const val PICK_FILE = 2
    }

    private lateinit var wanted: String
    private lateinit var texture: TextureView
    private lateinit var status: android.widget.TextView
    private val worker = HandlerThread("qr").apply { start() }
    private val workerHandler = Handler(worker.looper)
    private var camera: CameraDevice? = null
    private var session: CameraCaptureSession? = null
    private var reader: ImageReader? = null
    @Volatile private var busy = false
    @Volatile private var done = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // What the camera sees may be a secret: no screenshots or previews.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        wanted = intent.getStringExtra(EXTRA_WANTED) ?: WANT_TOTP
        val root = FrameLayout(this).apply { setBackgroundColor(Color.BLACK) }
        texture = TextureView(this)
        root.addView(texture, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        val panel = column(20).apply { setBackgroundColor(getColor(R.color.panel)) }
        panel.add(label(getString(R.string.scan_qr), 18f, bold = true))
        status = label(getString(if (wanted == WANT_SETUP) R.string.scan_hint_setup else R.string.scan_hint_totp), 14f, muted = true)
        panel.add(status, top = 4)
        val buttons = row()
        buttons.add(plainButton(getString(R.string.choose_file)) { pickFile() }, width = 0, weight = 1f)
        buttons.add(plainButton(getString(R.string.cancel)) { finish() }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
        panel.add(buttons, top = 8)
        root.addView(panel, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.BOTTOM))
        setContentView(root)
    }

    override fun onResume() {
        super.onResume()
        if (done) return
        if (checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
            startWhenReady()
        } else {
            requestPermissions(arrayOf(Manifest.permission.CAMERA), ASK_CAMERA)
        }
    }

    override fun onPause() {
        super.onPause()
        stopCamera()
    }

    override fun onDestroy() {
        super.onDestroy()
        worker.quitSafely()
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        if (requestCode != ASK_CAMERA) return
        if (grantResults.firstOrNull() == PackageManager.PERMISSION_GRANTED) startWhenReady() else status.text = getString(R.string.camera_denied)
    }

    private fun startWhenReady() {
        if (texture.isAvailable) return openCamera()
        texture.surfaceTextureListener = object : TextureView.SurfaceTextureListener {
            override fun onSurfaceTextureAvailable(surface: SurfaceTexture, width: Int, height: Int) = openCamera()
            override fun onSurfaceTextureSizeChanged(surface: SurfaceTexture, width: Int, height: Int) {}
            override fun onSurfaceTextureDestroyed(surface: SurfaceTexture): Boolean = true
            override fun onSurfaceTextureUpdated(surface: SurfaceTexture) {}
        }
    }

    @Suppress("DEPRECATION")
    private fun openCamera() {
        val manager = getSystemService(CameraManager::class.java) ?: return
        val id = try {
            manager.cameraIdList.firstOrNull { manager.getCameraCharacteristics(it).get(CameraCharacteristics.LENS_FACING) == CameraCharacteristics.LENS_FACING_BACK }
                ?: manager.cameraIdList.firstOrNull()
        } catch (e: Exception) {
            null
        } ?: run {
            status.text = getString(R.string.camera_denied)
            return
        }
        val map = try {
            manager.getCameraCharacteristics(id).get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP)
        } catch (e: Exception) {
            null
        }
        // Large enough to read a small code, small enough to decode quickly;
        // the preview takes a size the camera offers for it too.
        fun closest(sizes: Array<android.util.Size>?) = sizes?.minByOrNull { Math.abs(it.width * it.height - 1280 * 720) }
        val size = closest(map?.getOutputSizes(ImageFormat.YUV_420_888)) ?: android.util.Size(640, 480)
        val previewSize = closest(map?.getOutputSizes(SurfaceTexture::class.java)) ?: size
        val frames = ImageReader.newInstance(size.width, size.height, ImageFormat.YUV_420_888, 2)
        frames.setOnImageAvailableListener({ source ->
            val image = source.acquireLatestImage() ?: return@setOnImageAvailableListener
            if (busy || done) {
                image.close()
                return@setOnImageAvailableListener
            }
            busy = true
            // The luminance plane is the greyscale picture.
            val plane = image.planes[0]
            val bytes = ByteArray(plane.buffer.remaining()).also { plane.buffer.get(it) }
            val (width, height, stride) = Triple(image.width, image.height, plane.rowStride)
            image.close()
            look(bytes, width, height, stride)
            busy = false
        }, workerHandler)
        reader = frames
        try {
            manager.openCamera(id, object : CameraDevice.StateCallback() {
                override fun onOpened(device: CameraDevice) {
                    camera = device
                    val surfaceTexture = texture.surfaceTexture ?: return
                    surfaceTexture.setDefaultBufferSize(previewSize.width, previewSize.height)
                    val preview = Surface(surfaceTexture)
                    try {
                        startSession(device, preview, frames)
                    } catch (e: Exception) {
                        // A camera that cannot stream: the file is still there.
                        device.close()
                        runOnUiThread { status.text = getString(R.string.camera_denied) }
                    }
                }

                override fun onDisconnected(device: CameraDevice) = device.close()
                override fun onError(device: CameraDevice, error: Int) {
                    device.close()
                    runOnUiThread { status.text = getString(R.string.camera_denied) }
                }
            }, workerHandler)
        } catch (e: Exception) {
            status.text = getString(R.string.camera_denied)
        }
    }

    @Suppress("DEPRECATION")
    private fun startSession(device: CameraDevice, preview: Surface, frames: ImageReader) {
        device.createCaptureSession(listOf(preview, frames.surface), object : CameraCaptureSession.StateCallback() {
            override fun onConfigured(created: CameraCaptureSession) {
                session = created
                try {
                    val request = device.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW).apply {
                        addTarget(preview)
                        addTarget(frames.surface)
                        set(CaptureRequest.CONTROL_AF_MODE, CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE)
                    }
                    created.setRepeatingRequest(request.build(), null, workerHandler)
                } catch (e: Exception) {
                    // Closed meanwhile, or a camera that cannot stream.
                    runOnUiThread { if (!done) status.text = getString(R.string.camera_denied) }
                }
            }

            override fun onConfigureFailed(created: CameraCaptureSession) {
                runOnUiThread { status.text = getString(R.string.camera_denied) }
            }
        }, workerHandler)
    }

    private fun stopCamera() {
        try {
            session?.close()
            camera?.close()
            reader?.close()
        } catch (e: Exception) {
            // Already closed.
        }
        session = null
        camera = null
        reader = null
    }

    /** Whether a code holds what is wanted. */
    private fun accepts(content: String): Boolean = try {
        if (wanted == WANT_SETUP) {
            Native.obj("parseSetupLink", JSONObject().put("text", content))
            true
        } else {
            content.startsWith("otpauth://") && Native.obj("totp", JSONObject().put("uri", content).put("now", System.currentTimeMillis() / 1000)).has("code")
        }
    } catch (e: Exception) {
        false
    }

    /** Looks for the wanted code in a greyscale picture; answers and closes when found. */
    private fun look(pixels: ByteArray, width: Int, height: Int, stride: Int): Boolean {
        val found = JSONArray(Native.decodeQr(pixels, width, height, stride))
        for (i in 0 until found.length()) {
            val content = found.getString(i)
            if (!accepts(content)) continue
            done = true
            runOnUiThread {
                setResult(RESULT_OK, Intent().putExtra(EXTRA_CONTENT, content))
                finish()
            }
            return true
        }
        return false
    }

    private fun pickFile() {
        val pick = Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*")
            .putExtra(Intent.EXTRA_MIME_TYPES, arrayOf("image/*", "application/pdf"))
        try {
            @Suppress("DEPRECATION")
            startActivityForResult(pick, PICK_FILE)
        } catch (e: Exception) {
            // No document picker.
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
        val uri = data?.data
        if (requestCode != PICK_FILE || resultCode != RESULT_OK || uri == null) return
        status.text = getString(R.string.scan_looking)
        thread {
            val found = try {
                pictures(uri).any { picture ->
                    val (width, height) = picture.width to picture.height
                    val grey = greyscale(picture)
                    picture.recycle()
                    look(grey, width, height, width)
                }
            } catch (e: Exception) {
                false
            }
            if (!found) runOnUiThread { status.text = getString(if (wanted == WANT_SETUP) R.string.qr_not_found_setup else R.string.qr_not_found_totp) }
        }
    }

    /** The picture in an image file, or the first pages of a PDF. */
    private fun pictures(uri: Uri): Sequence<Bitmap> {
        val type = contentResolver.getType(uri) ?: ""
        if (type == "application/pdf") {
            return sequence {
                contentResolver.openFileDescriptor(uri, "r")?.use { descriptor ->
                    PdfRenderer(descriptor).use { pdf ->
                        for (index in 0 until minOf(pdf.pageCount, 3)) {
                            pdf.openPage(index).use { page ->
                                val scale = 1600f / maxOf(page.width, page.height)
                                val bitmap = Bitmap.createBitmap((page.width * scale).toInt(), (page.height * scale).toInt(), Bitmap.Config.ARGB_8888)
                                bitmap.eraseColor(Color.WHITE)
                                page.render(bitmap, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
                                yield(bitmap)
                            }
                        }
                    }
                }
            }
        }
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        contentResolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, bounds) }
        var sample = 1
        while (maxOf(bounds.outWidth, bounds.outHeight) / sample > 2400) sample *= 2
        val bitmap = contentResolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, BitmapFactory.Options().apply { inSampleSize = sample }) }
        return if (bitmap != null) sequenceOf(bitmap) else emptySequence()
    }

    private fun greyscale(bitmap: Bitmap): ByteArray {
        val pixels = IntArray(bitmap.width * bitmap.height)
        bitmap.getPixels(pixels, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)
        return ByteArray(pixels.size) { i ->
            val p = pixels[i]
            ((Color.red(p) * 299 + Color.green(p) * 587 + Color.blue(p) * 114) / 1000).toByte()
        }
    }
}

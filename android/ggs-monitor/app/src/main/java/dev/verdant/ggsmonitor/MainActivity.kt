package dev.verdant.ggsmonitor

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

class MainActivity : AppCompatActivity(), GgsBleClient.Listener {
    private lateinit var statusView: TextView
    private lateinit var frameLog: TextView
    private lateinit var frameScroll: ScrollView
    private lateinit var ble: GgsBleClient
    private val capture = CaptureStore()

    private var permissionState: String = "unknown"
    private var deviceState: String = "none"
    private var lastError: String? = null

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { result ->
        permissionState = if (result.values.all { it }) "granted" else "denied"
        renderStatus()
        if (permissionState != "granted") {
            lastError = "BLE permissions denied. Scan is blocked."
            renderStatus()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        statusView = findViewById(R.id.statusView)
        frameLog = findViewById(R.id.frameLog)
        frameScroll = findViewById(R.id.frameScroll)
        ble = GgsBleClient(this, this)

        findViewById<Button>(R.id.permissionsButton).setOnClickListener { requestBlePermissions() }
        findViewById<Button>(R.id.scanButton).setOnClickListener { onScanClicked() }
        findViewById<Button>(R.id.disconnectButton).setOnClickListener { ble.disconnect() }
        findViewById<Button>(R.id.clearButton).setOnClickListener {
            capture.clear()
            frameLog.text = capture.renderLog()
            renderStatus()
        }
        findViewById<Button>(R.id.exportButton).setOnClickListener { exportCapture() }

        permissionState = if (hasBlePermissions()) "granted" else "needed"
        renderStatus()
        frameLog.text = capture.renderLog()
    }

    override fun onDestroy() {
        ble.release()
        super.onDestroy()
    }

    private fun onScanClicked() {
        lastError = null
        if (!hasBlePermissions()) {
            permissionState = "needed"
            renderStatus()
            requestBlePermissions()
            return
        }
        permissionState = "granted"
        ble.startScan()
        renderStatus()
    }

    private fun requestBlePermissions() {
        permissionLauncher.launch(requiredPermissions())
    }

    private fun requiredPermissions(): Array<String> {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            arrayOf(
                Manifest.permission.BLUETOOTH_SCAN,
                Manifest.permission.BLUETOOTH_CONNECT,
            )
        } else {
            arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
        }
    }

    private fun hasBlePermissions(): Boolean {
        return requiredPermissions().all { permission ->
            ContextCompat.checkSelfPermission(this, permission) == PackageManager.PERMISSION_GRANTED
        }
    }

    private fun exportCapture() {
        val meta = mapOf(
            "app" to "GGS Monitor",
            "package" to packageName,
            "device_name_filter" to GgsBleClient.DEVICE_NAME,
            "connection" to ble.connectionState,
            "bluetooth" to ble.bluetoothState(),
            "versionName" to versionName(),
            "negotiated_mtu" to (ble.negotiatedMtu?.toString() ?: "unknown"),
            "mtu" to ble.mtuLine(),
            "decode" to "locked_unproven_vendor_key",
        )
        val body = capture.exportText(meta)
        val dir = File(cacheDir, "captures").apply { mkdirs() }
        val stamp = utcStamp()
        val file = File(dir, "ggs-ff01-$stamp.txt")
        file.writeText(body)
        val uri = FileProvider.getUriForFile(this, "$packageName.files", file)
        val share = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, "GGS Monitor FF01 capture")
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        startActivity(Intent.createChooser(share, "Export capture"))
        Toast.makeText(this, "Local export chooser opened (no cloud).", Toast.LENGTH_SHORT).show()
    }

    override fun onStatus(message: String) {
        runOnUiThread {
            lastError = null
            renderStatus(extra = message)
        }
    }

    override fun onDeviceFound(name: String, addressRedacted: Boolean) {
        runOnUiThread {
            deviceState = if (addressRedacted) name else name
            renderStatus(extra = "Found $name (MAC not shown).")
        }
    }

    override fun onConnection(state: String) {
        runOnUiThread { renderStatus() }
    }

    override fun onMtu(mtu: Int, gattStatus: Int) {
        runOnUiThread {
            renderStatus(extra = "ATT MTU negotiated=$mtu gatt_status=$gattStatus")
        }
    }

    override fun onFf01(bytes: ByteArray) {
        runOnUiThread {
            capture.add(bytes, System.currentTimeMillis())
            frameLog.text = capture.renderLog()
            frameScroll.post { frameScroll.fullScroll(ScrollView.FOCUS_DOWN) }
            renderStatus()
        }
    }

    override fun onError(message: String) {
        runOnUiThread {
            lastError = message
            renderStatus()
        }
    }

    private fun renderStatus(extra: String? = null) {
        val lastTs = capture.lastEpochMs?.let { ms ->
            val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS 'UTC'", Locale.US)
            fmt.timeZone = TimeZone.getTimeZone("UTC")
            fmt.format(Date(ms))
        } ?: "-"
        val bluetoothAdapterPresent = packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE)
        val lines = listOf(
            "permissions: $permissionState",
            "bluetooth: ${ble.bluetoothState()} adapter=${if (bluetoothAdapterPresent) "le_feature" else "no_le_feature"}",
            "android_sdk: ${Build.VERSION.SDK_INT}  adapter_on=${BluetoothAdapter.getDefaultAdapter()?.isEnabled ?: false}",
            "device: $deviceState (filter=${GgsBleClient.DEVICE_NAME})",
            "connection: ${ble.connectionState}",
            "mtu: ${ble.mtuLine()}",
            "packets: ${capture.packetCount}  bytes: ${capture.byteCount}  last: $lastTs",
            capture.completeSummary(),
            "retained_frames: ${capture.snapshot().size}/${CaptureStore.MAX_FRAMES}",
            "app: ${versionName()}  write_policy: never writeCharacteristic; FF02 unused; CCCD subscribe only",
            "decode: LOCKED — no plaintext sensors until proven key material",
            extra?.let { "note: $it" },
            lastError?.let { "error: $it" },
        ).filterNotNull()
        statusView.text = lines.joinToString("\n")
    }

    private fun utcStamp(): String {
        val fmt = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US)
        fmt.timeZone = TimeZone.getTimeZone("UTC")
        return fmt.format(Date())
    }

    private fun versionName(): String {
        return try {
            packageManager.getPackageInfo(packageName, 0).versionName ?: "unknown"
        } catch (_: Exception) {
            "unknown"
        }
    }
}

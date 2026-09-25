package dev.verdant.ggsmonitor

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import androidx.annotation.RequiresApi
import java.util.UUID

/**
 * Receive-only GGS BLE client.
 *
 * Subscribes to FF01 notifications. After services are discovered, requests a
 * large ATT MTU (517 preferred). The only GATT write is the CCCD descriptor
 * required to enable notifications. [BluetoothGatt.writeCharacteristic] is never
 * called — including FF02.
 */
class GgsBleClient(
    context: Context,
    private val listener: Listener,
) {
    interface Listener {
        fun onStatus(message: String)
        fun onDeviceFound(name: String, addressRedacted: Boolean)
        fun onConnection(state: String)
        fun onMtu(mtu: Int, gattStatus: Int)
        fun onFf01(bytes: ByteArray)
        fun onError(message: String)
    }

    private val appContext = context.applicationContext
    private val handler = Handler(Looper.getMainLooper())
    private val bluetoothManager = appContext.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    private val adapter: BluetoothAdapter? = bluetoothManager.adapter

    private var gatt: BluetoothGatt? = null
    private var scanning = false
    private var subscribedFf01 = false
    private var mtuRequestOutstanding = false
    @Volatile var connectionState: String = "idle"
        private set
    @Volatile var lastDeviceName: String? = null
        private set
    @Volatile var negotiatedMtu: Int? = null
        private set
    @Volatile var mtuStatus: String = "not_requested"
        private set

    fun bluetoothState(): String {
        val bt = adapter ?: return "missing_adapter"
        return when (bt.state) {
            BluetoothAdapter.STATE_ON -> "on"
            BluetoothAdapter.STATE_OFF -> "off"
            BluetoothAdapter.STATE_TURNING_ON -> "turning_on"
            BluetoothAdapter.STATE_TURNING_OFF -> "turning_off"
            else -> "unknown"
        }
    }

    fun mtuLine(): String {
        val current = negotiatedMtu?.toString() ?: "-"
        return "negotiated=$current preferred=$PREFERRED_MTU status=$mtuStatus"
    }

    @SuppressLint("MissingPermission")
    fun startScan(timeoutMs: Long = 15_000L) {
        val bt = adapter
        if (bt == null || !bt.isEnabled) {
            listener.onError("Bluetooth is off or unavailable.")
            return
        }
        stopScan()
        closeGatt()
        connectionState = "scanning"
        listener.onConnection(connectionState)
        listener.onStatus("Scanning for exact name $DEVICE_NAME")
        val scanner = bt.bluetoothLeScanner
        if (scanner == null) {
            listener.onError("BLE scanner unavailable.")
            connectionState = "idle"
            listener.onConnection(connectionState)
            return
        }
        val filter = ScanFilter.Builder().setDeviceName(DEVICE_NAME).build()
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()
        scanning = true
        scanner.startScan(listOf(filter), settings, scanCallback)
        handler.postDelayed({
            if (scanning && connectionState == "scanning") {
                stopScan()
                connectionState = "idle"
                listener.onConnection(connectionState)
                listener.onError("$DEVICE_NAME not found in scan window. Hardware not verified on this runner.")
            }
        }, timeoutMs)
    }

    @SuppressLint("MissingPermission")
    fun disconnect() {
        stopScan()
        closeGatt()
        connectionState = "disconnected"
        listener.onConnection(connectionState)
        listener.onStatus("Disconnected (receive-only session ended).")
    }

    @SuppressLint("MissingPermission")
    fun release() {
        handler.removeCallbacksAndMessages(null)
        stopScan()
        closeGatt()
    }

    @SuppressLint("MissingPermission")
    private fun stopScan() {
        if (!scanning) return
        scanning = false
        try {
            adapter?.bluetoothLeScanner?.stopScan(scanCallback)
        } catch (_: Exception) {
            // Scanner may already be down.
        }
    }

    @SuppressLint("MissingPermission")
    private fun closeGatt() {
        handler.removeCallbacks(mtuFallback)
        try {
            gatt?.disconnect()
        } catch (_: Exception) {
        }
        try {
            gatt?.close()
        } catch (_: Exception) {
        }
        gatt = null
        subscribedFf01 = false
        mtuRequestOutstanding = false
        negotiatedMtu = null
        mtuStatus = "not_requested"
    }

    private val scanCallback = object : ScanCallback() {
        @SuppressLint("MissingPermission")
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val device = result.device ?: return
            val name = device.name ?: result.scanRecord?.deviceName
            if (name != DEVICE_NAME) return
            if (connectionState != "scanning") return
            stopScan()
            lastDeviceName = name
            listener.onDeviceFound(name, addressRedacted = true)
            connect(device)
        }

        override fun onScanFailed(errorCode: Int) {
            scanning = false
            connectionState = "idle"
            listener.onConnection(connectionState)
            listener.onError("Scan failed (code $errorCode).")
        }
    }

    @SuppressLint("MissingPermission")
    private fun connect(device: BluetoothDevice) {
        connectionState = "connecting"
        listener.onConnection(connectionState)
        listener.onStatus("Connecting read-only; will request MTU $PREFERRED_MTU then subscribe to FF01 only.")
        gatt = device.connectGatt(appContext, false, gattCallback, BluetoothDevice.TRANSPORT_LE)
    }

    private val mtuFallback = Runnable {
        if (!subscribedFf01 && mtuRequestOutstanding) {
            mtuRequestOutstanding = false
            mtuStatus = "timeout_using_default"
            listener.onStatus("MTU callback not received; subscribing at default ATT MTU 23.")
            val current = gatt
            if (current != null) {
                subscribeFf01(current)
            }
        }
    }

    private val gattCallback = object : BluetoothGattCallback() {
        @SuppressLint("MissingPermission")
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                connectionState = "connected_discovering"
                listener.onConnection(connectionState)
                listener.onStatus("Connected; discovering services (no FF02 writes).")
                gatt.discoverServices()
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                handler.removeCallbacks(mtuFallback)
                subscribedFf01 = false
                mtuRequestOutstanding = false
                connectionState = "disconnected"
                listener.onConnection(connectionState)
                listener.onStatus("GATT disconnected (status=$status).")
            }
        }

        @SuppressLint("MissingPermission")
        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                listener.onError("Service discovery failed (status=$status).")
                return
            }
            connectionState = "requesting_mtu"
            listener.onConnection(connectionState)
            listener.onStatus("Services discovered; requesting ATT MTU $PREFERRED_MTU (fallback to 23).")
            mtuStatus = "requesting"
            val accepted = gatt.requestMtu(PREFERRED_MTU)
            if (!accepted) {
                mtuRequestOutstanding = false
                mtuStatus = "request_rejected"
                listener.onStatus("MTU request rejected by stack; continuing subscribe at default ATT MTU.")
                subscribeFf01(gatt)
                return
            }
            mtuRequestOutstanding = true
            handler.removeCallbacks(mtuFallback)
            handler.postDelayed(mtuFallback, MTU_CALLBACK_TIMEOUT_MS)
        }

        @SuppressLint("MissingPermission")
        override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
            handler.removeCallbacks(mtuFallback)
            mtuRequestOutstanding = false
            negotiatedMtu = mtu
            mtuStatus = if (status == BluetoothGatt.GATT_SUCCESS) {
                "negotiated"
            } else {
                "callback_status_$status"
            }
            listener.onMtu(mtu, status)
            listener.onStatus(
                "Negotiated ATT MTU=$mtu (preferred=$PREFERRED_MTU, gatt_status=$status).",
            )
            subscribeFf01(gatt)
        }

        override fun onDescriptorWrite(
            gatt: BluetoothGatt,
            descriptor: BluetoothGattDescriptor,
            status: Int,
        ) {
            if (descriptor.uuid != CCCD_UUID) {
                listener.onError("Unexpected descriptor write; aborting.")
                return
            }
            if (status == BluetoothGatt.GATT_SUCCESS) {
                connectionState = "subscribed_ff01"
                listener.onConnection(connectionState)
                listener.onStatus(
                    "Subscribed to FF01 notifications. MTU ${mtuLine()}. Decode remains locked.",
                )
            } else {
                subscribedFf01 = false
                listener.onError("CCCD write failed (status=$status).")
            }
        }

        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
        ) {
            deliverFf01(characteristic, characteristic.value)
        }

        @RequiresApi(33)
        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray,
        ) {
            deliverFf01(characteristic, value)
        }
    }

    private fun deliverFf01(characteristic: BluetoothGattCharacteristic, value: ByteArray?) {
        if (characteristic.uuid != FF01_UUID) return
        if (value == null) return
        listener.onFf01(value.copyOf())
    }

    @SuppressLint("MissingPermission")
    private fun subscribeFf01(gatt: BluetoothGatt) {
        if (subscribedFf01) return
        val notify = findFf01(gatt)
        if (notify == null) {
            listener.onError("FF01 notify characteristic not found. No writes will be attempted.")
            connectionState = "connected_no_ff01"
            listener.onConnection(connectionState)
            return
        }
        val enabled = gatt.setCharacteristicNotification(notify, true)
        if (!enabled) {
            listener.onError("setCharacteristicNotification(FF01) failed.")
            return
        }
        val cccd = notify.getDescriptor(CCCD_UUID)
        if (cccd == null) {
            listener.onError("FF01 CCCD missing; cannot subscribe without descriptor write.")
            return
        }
        // Descriptor write only — never writeCharacteristic / never FF02.
        cccd.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
        val wrote = gatt.writeDescriptor(cccd)
        if (!wrote) {
            listener.onError("CCCD write request was not accepted.")
            return
        }
        subscribedFf01 = true
        connectionState = "subscribing"
        listener.onConnection(connectionState)
    }

    private fun findFf01(gatt: BluetoothGatt): BluetoothGattCharacteristic? {
        for (service in gatt.services) {
            val characteristic = service.getCharacteristic(FF01_UUID)
            if (characteristic != null) return characteristic
        }
        return null
    }

    companion object {
        const val DEVICE_NAME: String = "SF-GGS-CB"
        const val PREFERRED_MTU: Int = 517
        const val DEFAULT_ATT_MTU: Int = 23
        const val MTU_CALLBACK_TIMEOUT_MS: Long = 4_000L
        val FF01_UUID: UUID = UUID.fromString("0000ff01-0000-1000-8000-00805f9b34fb")
        val FF02_UUID: UUID = UUID.fromString("0000ff02-0000-1000-8000-00805f9b34fb")
        val SERVICE_UUID: UUID = UUID.fromString("0000ff00-0000-1000-8000-00805f9b34fb")
        val CCCD_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

        /** Unused except to keep SERVICE_UUID referenced for documentation/tests. */
        fun documentedServiceParcel(): ParcelUuid = ParcelUuid(SERVICE_UUID)
    }
}

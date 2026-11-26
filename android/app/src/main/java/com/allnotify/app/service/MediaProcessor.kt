package com.allnotify.app.service

import android.app.Notification
import android.content.ContentResolver
import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import android.graphics.drawable.Icon
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Parcelable
import com.allnotify.app.net.BlobApiClient
import java.io.ByteArrayOutputStream
import kotlin.math.roundToInt

data class EncodedIcon(
    val bytes: ByteArray,
    val sha256: String
)

data class EncodedImageAttachment(
    val bytes: ByteArray,
    val mime: String,
    val width: Int,
    val height: Int,
    val sha256: String
)

object MediaProcessor {
    const val ICON_SIZE_PX = 64
    const val MAX_IMAGE_DIM_PX = 800
    const val MAX_IMAGE_PLAINTEXT_BYTES = 524_288 // 512 KB

    fun encodeAppIcon(drawable: Drawable): EncodedIcon? {
        val rawBitmap = if (drawable is BitmapDrawable && drawable.bitmap != null) {
            drawable.bitmap
        } else {
            val bmp = Bitmap.createBitmap(ICON_SIZE_PX, ICON_SIZE_PX, Bitmap.Config.ARGB_8888)
            val canvas = Canvas(bmp)
            drawable.setBounds(0, 0, canvas.width, canvas.height)
            drawable.draw(canvas)
            bmp
        }
        val scaled = if (rawBitmap.width == ICON_SIZE_PX && rawBitmap.height == ICON_SIZE_PX) {
            rawBitmap
        } else {
            Bitmap.createScaledBitmap(rawBitmap, ICON_SIZE_PX, ICON_SIZE_PX, true)
        }
        val bytes = compressWebp(scaled, 80) ?: return null
        if (bytes.isEmpty()) return null
        return EncodedIcon(bytes = bytes, sha256 = BlobApiClient.sha256Hex(bytes))
    }

    fun compressImageAttachment(bitmap: Bitmap): EncodedImageAttachment? {
        val scaled = scaleToMaxDimension(bitmap, MAX_IMAGE_DIM_PX)
        val width = scaled.width.coerceIn(1, MAX_IMAGE_DIM_PX)
        val height = scaled.height.coerceIn(1, MAX_IMAGE_DIM_PX)

        // Try WebP first at decreasing quality levels.
        for (quality in intArrayOf(82, 70, 55, 40)) {
            val bytes = compressWebp(scaled, quality) ?: continue
            if (bytes.size in 1..MAX_IMAGE_PLAINTEXT_BYTES) {
                return EncodedImageAttachment(
                    bytes = bytes,
                    mime = "image/webp",
                    width = width,
                    height = height,
                    sha256 = BlobApiClient.sha256Hex(bytes)
                )
            }
        }

        // Fallback to JPEG if WebP still exceeded 512 KB.
        for (quality in intArrayOf(75, 55, 40)) {
            val out = ByteArrayOutputStream()
            if (scaled.compress(Bitmap.CompressFormat.JPEG, quality, out)) {
                val bytes = out.toByteArray()
                if (bytes.size in 1..MAX_IMAGE_PLAINTEXT_BYTES) {
                    return EncodedImageAttachment(
                        bytes = bytes,
                        mime = "image/jpeg",
                        width = width,
                        height = height,
                        sha256 = BlobApiClient.sha256Hex(bytes)
                    )
                }
            }
        }
        return null
    }

    fun scaleToMaxDimension(bitmap: Bitmap, maxDim: Int): Bitmap {
        val w = bitmap.width
        val h = bitmap.height
        if (w <= maxDim && h <= maxDim) return bitmap
        val ratio = maxDim.toFloat() / maxOf(w, h).toFloat()
        val newW = (w * ratio).roundToInt().coerceAtLeast(1)
        val newH = (h * ratio).roundToInt().coerceAtLeast(1)
        return Bitmap.createScaledBitmap(bitmap, newW, newH, true)
    }

    @Suppress("DEPRECATION")
    fun extractAttachmentBitmap(context: Context, extras: Bundle): Bitmap? {
        // 1. BigPictureStyle EXTRA_PICTURE
        val directBitmap = extras.getParcelable<Bitmap>(Notification.EXTRA_PICTURE)
        if (directBitmap != null) return directBitmap

        // 2. Android 12+ EXTRA_PICTURE_ICON
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val picIcon = extras.getParcelable<Icon>(Notification.EXTRA_PICTURE_ICON)
            if (picIcon != null) {
                if (picIcon.type == Icon.TYPE_URI || picIcon.type == Icon.TYPE_URI_ADAPTIVE_BITMAP) {
                    val uri = picIcon.uri
                    val sampled = decodeSampledUri(context, uri)
                    if (sampled != null) return sampled
                    // Only fall back to loadDrawable for android.resource:// URIs (e.g. VectorDrawable XML);
                    // never fall back to unsampled decoding for content:// or file:// image URIs.
                    if (uri.scheme != ContentResolver.SCHEME_ANDROID_RESOURCE) {
                        return null
                    }
                }
                val drawable = runCatching { picIcon.loadDrawable(context) }.getOrNull()
                if (drawable != null) {
                    return drawableToBitmap(drawable)
                }
            }
        }

        // 3. MessagingStyle latest message dataUri image (subsampled to avoid OOM on high-res URIs)
        val messages = extras.getParcelableArray(Notification.EXTRA_MESSAGES) ?: return null
        for (i in messages.lastIndex downTo 0) {
            val bundle = messages[i] as? Bundle ?: continue
            val mimeType = bundle.getString("type") ?: continue
            if (!mimeType.startsWith("image/")) continue
            val uri = bundle.getParcelable<Parcelable>("uri") as? Uri ?: continue
            val decoded = decodeSampledUri(context, uri)
            if (decoded != null) return decoded
        }
        return null
    }

    internal fun calculateInSampleSize(width: Int, height: Int, maxDim: Int): Int {
        if (width <= 0 || height <= 0 || maxDim <= 0) return 1
        var inSampleSize = 1
        val longest = maxOf(width, height)
        while (longest / (inSampleSize * 2) >= maxDim) {
            inSampleSize *= 2
        }
        return inSampleSize
    }

    internal fun decodeSampledUri(
        context: Context,
        uri: Uri,
        maxDim: Int = MAX_IMAGE_DIM_PX
    ): Bitmap? {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        val opened = runCatching {
            context.contentResolver.openInputStream(uri)?.use { stream ->
                BitmapFactory.decodeStream(stream, null, bounds)
                true
            } ?: false
        }.getOrDefault(false)
        if (!opened || bounds.outWidth <= 0 || bounds.outHeight <= 0) {
            return null
        }
        val decodeOpts = BitmapFactory.Options().apply {
            inSampleSize = calculateInSampleSize(bounds.outWidth, bounds.outHeight, maxDim)
        }
        return runCatching {
            context.contentResolver.openInputStream(uri)?.use { stream ->
                BitmapFactory.decodeStream(stream, null, decodeOpts)
            }
        }.getOrNull()
    }

    internal fun drawableToBitmap(drawable: Drawable): Bitmap {
        if (drawable is BitmapDrawable && drawable.bitmap != null) {
            return drawable.bitmap
        }
        val rawW = drawable.intrinsicWidth.coerceAtLeast(1)
        val rawH = drawable.intrinsicHeight.coerceAtLeast(1)
        val (w, h) = if (rawW > MAX_IMAGE_DIM_PX || rawH > MAX_IMAGE_DIM_PX) {
            val ratio = MAX_IMAGE_DIM_PX.toFloat() / maxOf(rawW, rawH).toFloat()
            (rawW * ratio).roundToInt().coerceAtLeast(1) to (rawH * ratio).roundToInt().coerceAtLeast(1)
        } else {
            rawW to rawH
        }
        val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bmp)
        drawable.setBounds(0, 0, w, h)
        drawable.draw(canvas)
        return bmp
    }

    @Suppress("DEPRECATION")
    private fun compressWebp(bitmap: Bitmap, quality: Int): ByteArray? {
        val out = ByteArrayOutputStream()
        val format = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Bitmap.CompressFormat.WEBP_LOSSY
        } else {
            Bitmap.CompressFormat.WEBP
        }
        return if (bitmap.compress(format, quality, out)) out.toByteArray() else null
    }
}

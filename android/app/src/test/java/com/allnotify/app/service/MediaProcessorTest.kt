package com.allnotify.app.service

import android.app.Notification
import android.content.Context
import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.net.Uri
import android.os.Bundle
import androidx.test.core.app.ApplicationProvider
import com.allnotify.app.data.BlobCacheManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.FileOutputStream

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class MediaProcessorTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun scaleToMaxDimensionPreservesAspectRatioAndClampsTo800() {
        val landscape = Bitmap.createBitmap(1600, 1200, Bitmap.Config.ARGB_8888)
        val scaledLandscape = MediaProcessor.scaleToMaxDimension(landscape, 800)
        assertEquals(800, scaledLandscape.width)
        assertEquals(600, scaledLandscape.height)

        val portrait = Bitmap.createBitmap(900, 1800, Bitmap.Config.ARGB_8888)
        val scaledPortrait = MediaProcessor.scaleToMaxDimension(portrait, 800)
        assertEquals(400, scaledPortrait.width)
        assertEquals(800, scaledPortrait.height)

        val small = Bitmap.createBitmap(300, 200, Bitmap.Config.ARGB_8888)
        val unchanged = MediaProcessor.scaleToMaxDimension(small, 800)
        assertEquals(300, unchanged.width)
        assertEquals(200, unchanged.height)
    }

    @Test
    fun encodeAppIconAndCompressImageMeetProtocolBudgets() {
        val icon = MediaProcessor.encodeAppIcon(ColorDrawable(Color.BLUE))
        assertNotNull(icon)
        assertTrue(icon!!.bytes.isNotEmpty())
        assertTrue(BlobCacheManager.SHA256_REGEX.matches(icon.sha256))

        val big = Bitmap.createBitmap(1200, 900, Bitmap.Config.ARGB_8888)
        val encoded = MediaProcessor.compressImageAttachment(big)
        assertNotNull(encoded)
        assertTrue(encoded!!.width <= 800)
        assertTrue(encoded.height <= 800)
        assertTrue(encoded.bytes.size in 1..MediaProcessor.MAX_IMAGE_PLAINTEXT_BYTES)
        assertTrue(encoded.mime == "image/webp" || encoded.mime == "image/jpeg")
        assertTrue(BlobCacheManager.SHA256_REGEX.matches(encoded.sha256))
    }

    @Test
    fun extractAttachmentBitmapReadsExtraPicture() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val bmp = Bitmap.createBitmap(100, 80, Bitmap.Config.ARGB_8888)
        val extras = Bundle().apply {
            putParcelable(Notification.EXTRA_PICTURE, bmp)
        }
        val extracted = MediaProcessor.extractAttachmentBitmap(context, extras)
        assertNotNull(extracted)
        assertEquals(100, extracted!!.width)
        assertEquals(80, extracted.height)
    }

    @Test
    fun calculateInSampleSizeHandlesBoundariesAndLargeDimensions() {
        assertEquals(1, MediaProcessor.calculateInSampleSize(0, 0, 800))
        assertEquals(1, MediaProcessor.calculateInSampleSize(-10, 100, 800))
        assertEquals(1, MediaProcessor.calculateInSampleSize(800, 600, 800))
        assertEquals(1, MediaProcessor.calculateInSampleSize(1599, 1000, 800))
        assertEquals(2, MediaProcessor.calculateInSampleSize(1600, 1200, 800))
        assertEquals(4, MediaProcessor.calculateInSampleSize(4000, 3000, 800))
        assertEquals(4, MediaProcessor.calculateInSampleSize(1200, 3200, 800))
        assertEquals(8, MediaProcessor.calculateInSampleSize(12000, 9000, 800))
    }

    @Test
    fun extractAttachmentBitmapSubsamplesHighResMessagingUriAndHandlesCorruptUri() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val imgFile = tempFolder.newFile("highres.png")
        val bigBitmap = Bitmap.createBitmap(3200, 2400, Bitmap.Config.ARGB_8888)
        FileOutputStream(imgFile).use { out ->
            assertTrue(bigBitmap.compress(Bitmap.CompressFormat.PNG, 100, out))
        }

        val msgBundle = Bundle().apply {
            putString("type", "image/png")
            putParcelable("uri", Uri.fromFile(imgFile))
        }
        val extras = Bundle().apply {
            putParcelableArray(Notification.EXTRA_MESSAGES, arrayOf(msgBundle))
        }

        val decoded = MediaProcessor.extractAttachmentBitmap(context, extras)
        assertNotNull(decoded)
        assertEquals(800, decoded!!.width)
        assertEquals(600, decoded.height)

        // Missing/unopenable URI should return null cleanly without throwing.
        val missingFile = java.io.File(tempFolder.root, "missing.png")
        assertNull(MediaProcessor.decodeSampledUri(context, Uri.fromFile(missingFile)))
    }

    @Test
    fun extractAttachmentBitmapSubsamplesExtraPictureIconUriAndPreservesDrawableAspectRatio() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val imgFile = tempFolder.newFile("icon_highres.png")
        val bigBitmap = Bitmap.createBitmap(3200, 2400, Bitmap.Config.ARGB_8888)
        FileOutputStream(imgFile).use { out ->
            assertTrue(bigBitmap.compress(Bitmap.CompressFormat.PNG, 100, out))
        }

        val uriIcon = android.graphics.drawable.Icon.createWithContentUri(Uri.fromFile(imgFile))
        val extras = Bundle().apply {
            putParcelable(Notification.EXTRA_PICTURE_ICON, uriIcon)
        }
        val decoded = MediaProcessor.extractAttachmentBitmap(context, extras)
        assertNotNull(decoded)
        assertEquals(800, decoded!!.width)
        assertEquals(600, decoded.height)

        // Unopenable file:// Icon URI must return null without throwing or unsampled fallback.
        val missingFile = java.io.File(tempFolder.root, "missing_icon.png")
        val badIconExtras = Bundle().apply {
            putParcelable(
                Notification.EXTRA_PICTURE_ICON,
                android.graphics.drawable.Icon.createWithContentUri(Uri.fromFile(missingFile))
            )
        }
        assertNull(MediaProcessor.extractAttachmentBitmap(context, badIconExtras))

        // Non-square Drawable larger than MAX_IMAGE_DIM_PX must preserve aspect ratio in drawableToBitmap.
        val wideDrawable = object : ColorDrawable(Color.RED) {
            override fun getIntrinsicWidth(): Int = 1600
            override fun getIntrinsicHeight(): Int = 800
        }
        val rendered = MediaProcessor.drawableToBitmap(wideDrawable)
        assertEquals(800, rendered.width)
        assertEquals(400, rendered.height)
    }
}

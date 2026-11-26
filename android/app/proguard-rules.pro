# Keep Kotlinx Serialization generated serializers
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt
-keepclassmembers class kotlinx.serialization.json.** {
    *** Companion;
}
-keepclasseswithmembers class kotlinx.serialization.json.** {
    kotlinx.serialization.KSerializer serializer(...);
}
-keep,includedescriptorclasses class com.allnotify.app.protocol.**$$serializer { *; }
-keepclassmembers class com.allnotify.app.protocol.** {
    *** Companion;
}
-keepclasseswithmembers class com.allnotify.app.protocol.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# Tink references compile-only ErrorProne annotations
-dontwarn com.google.errorprone.annotations.CanIgnoreReturnValue
-dontwarn com.google.errorprone.annotations.CheckReturnValue
-dontwarn com.google.errorprone.annotations.Immutable
-dontwarn com.google.errorprone.annotations.RestrictedApi

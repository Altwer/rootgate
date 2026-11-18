# kotlinx.serialization
-keepattributes *Annotation*, InnerClasses
-keepclassmembers class dev.altfurr.rootgate.** {
    *** Companion;
}
-keepclasseswithmembers class dev.altfurr.rootgate.** {
    kotlinx.serialization.KSerializer serializer(...);
}

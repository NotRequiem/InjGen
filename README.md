InjGen is a program focused in detecting any external **JNI/JVMTI injection** into a Java program. As a PoC, it's designed to detect ghost clients in the Minecraft game

### Tested detections

> Vape Lite Client

> Vape V4 Client

> DoomsDay Client

> Slinky Client

> Sunset Client

> Karma Client


### Tested game clients
*This means that InjGen won't give a false positive in the following game clients:*

> Lunar Client (all versions)

> Feather Client (all versions)

> Minecraft Vanilla (1.7.10 - 1.21.4)

> LabyMod (not fully tested)

*InjGen won't false flag despite you using any of the above with OptiFine or Sodium (or any other non-JNI mod) with Forge or Fabric.*

### Known flags
1. Badlion Client will flag InjGen due to them performing JNI injections
2. Some other hacked clients like Entropy, Dream or Drip may be aswell detected if they perform blatant modifications to the JVM 

### Notes
JNI and JVMTI injections are not the only two injections in the world, if a client injects by using the Forge API (Vape Lite can do it), it won't be detected as using Forge doesn't imply memory changes in the JVM

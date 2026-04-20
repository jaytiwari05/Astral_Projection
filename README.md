
## Astral Projection - UDRL


Astral Projection is a Cobalt Strike UDRL (User-Defined Reflective Loader), that performs advanced module stomping.

The UDRL loads a module using `LoadLibraryExW`, then manipulates its internals by setting VEH to intercept strategic calls that allow it to steal the section handle of the sacrificial DLL and upgrade its access rights for later use in the sleep mask. During sleep it unmaps the module while keeping PEB entries intact, then remaps a fresh module to avoid any IOCs while sleeping. 

This project is built with [Crystal Palace](https://tradecraftgarden.org/crystalpalace.html). Some of the code was adopted from the [Crystal-Kit](https://github.com/rasta-mouse/Crystal-Kit) project.


A technical blog post covering the techniques used in detail can be found [here](https://kuwaitist.github.io/posts/Astral-Projection/)

---

### Profile

- Disable the sleepmask and stage obfuscations in Malleable C2.

```
stage {
    set sleep_mask "false";
    set cleanup "true";
    transform-obfuscate { }
}

post-ex {
    set cleanup "true";
    set smartinject "true";
}
```

- Copy `crystalpalace.jar` to your Cobalt Strike client directory.
- Load `Astral_Projection.cna`.

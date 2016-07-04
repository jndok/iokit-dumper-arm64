# iokit-dumper-arm64 + libdump
_iokit-dumper-arm64_ is the static iOS _AArch64_ version for [_iokit-dumper_]("https://github.com/jndok/iokit-dumper").
<br>
It uses a dumped 64-bit kernelcache to rebuild the IOKit classes hierarchy for a specific image in the kernelcache, and generate a _DOT_ graph for it. You can see some example generated graphs below, in the **Examples** section.

## How to use
Firstly, to generate _DOT_ graphs you will need `dot` installed. Do:

```
brew install graphviz
```

And test with:

```
dot -v
```

Now, the arguments accepted by _iokit-dumper-arm64_:

*   `-f`: It specifies the kernelcache path to work with.
*   `-o`: It specifies the output path. The output file name is auto-generated. If not specified, default path used will be `/tmp`.
*   `-n`: it specifies the image to dump name. If not specified, all images will be dumped. Pass the string `kernel` to dump the kernel hierarchy. Pass a KEXT bundle name (Ex. `com.apple.iokit.IOHIDFamily`) to dump that KEXT hierarchy.
*   `-c`: Auto convert. If specified, it automatically runs a dot command at the end of the dumping process to generate a PDF file containing the graph.

Example usage to dump kernel hierarchy to Desktop:
```
./iokit-dumper-arm64 -f /path/to/kernelcache.dump -n kernel -o /Users/$USER/Desktop/ -c
```

## libdump
`libdump` is a kind-of AArch64 emulator. It is quite sloppy and relies on `capstone`. It has been written specifically for this project, but it could become a totally separated project in the future.

## Notes
This tool has problems with new unencrypted kernelcaches, probably because of the decompression method used. It is unable to find the kernel image (at least on those I've tried), so it rebuilds the hierarchy of any KEXT but it doesn't link it to the kernel classes.

If you feel like contrinuting, do not hesitate doing so! Just submit a pull request. I would really appreciate some help.

Future updates are planned, and improvements are coming.

## Thanks
 *  i0n1c  (https://twitter.com/i0n1c) - for providing DOT source files from his tool (https://github.com/stefanesser/ios-kerneldocs). Was very useful to improve the DOT file generation code and for double checking my algorithm was working correctly.
 *  jlevin (https://twitter.com/Morpheus______) - for providing useful tools such as joker, which helped me out a lot with this project.

## Examples
Here are some generated graphs as an example:

#### IOAudio2Family
![com.apple.iokit.IOAudio2Family](http://jndoksarchive.altervista.org/com.apple.iokit.IOAudio2Family-dump.jpg)

#### IOHIDFamily
![com.apple.iokit.IOHIDFamily](http://jndoksarchive.altervista.org/com.apple.iokit.IOHIDFamily-dump.jpg)

#### IOAcceleratorFamily2
![com.apple.iokit.IOAcceleratorFamily2](http://jndoksarchive.altervista.org/com.apple.iokit.IOAcceleratorFamily2-dump.dot.jpg)

## TODO
A list of to-do for updates.
- [ ] Code cleanup
- [x] Unencrypted kernelcaches support
- [ ] Add graph customization and details

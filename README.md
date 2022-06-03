# HexagonDiffTest

This is the tool used for my master thesis ["Analysis of the Correctness of Qualcomm Hexagon Emulators and Decompilers via Differential Testing"](thesis.pdf).

## Dependencies

These are the versions of emulators/decompiler when the tool was used.

- hexagon-sim (In HEXAGON Tools 8.3.07)
- QEMU (Nov 1, 2021, commit hash `94ca4341`)
- binja-hexagon (Oct 20, 2021, commit hash `31993a3a`)
  - emILator (`ebd7ba26`)

## How to use

Make sure that HEXAGON SDK, Binary Ninja and [binja-hexagon](https://github.com/google/binja-hexagon) are installed in your computer.

Get the submodules:

```bash
git submodule update --init --recursive
```

### Building QEMU docker image

Apply the `qemu.patch` and build (If it does not work well, please uncomment the `docker-image-debian-hexagon-cross` related part in the script):

```bash
cd src/qemu-docker/qemu
git apply ../qemu.patch
./build_qemu_hexagon_docker.sh
```

Run the docker image:
```bash
docker run -p9000:9000 rbtree/qemu-hexagon
```

### Run

Run `src/test.py` to run the differential tester.

You can specify the number of cores:
```bash
python3 test.py -c 4
```

You can specify the packet to test:
```bash
python3 test.py -t packet.json
```
```json
[
    "Rd=convert_sf2uw(Rs)",
    "nop",
    "nop",
    "nop"
]
```

## Some notes

- `src/common/template_asm.elf` was built with `hexagon-unknown-linux-musl-clang` in the docker image.
- The port 9000 is hardcoded everywhere. If it's already used, please search `9000` and change by your hands.
- Also, the version of HEXAGON SDK is hardcoded in `src/Makefile`. Please change it if you're using a different version.
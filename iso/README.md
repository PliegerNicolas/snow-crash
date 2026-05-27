# SnowCrash.iso

It can or could be downloaded [here](https://cdn.intra.42.fr/isos/SnowCrash.iso).

It is specified it should be installed as a 64-bit VM.

### Inspection

To inspect it's content, it is possible to mount the `.iso` file as if it was a physical device (ex: USB stick). For this use the following commands:
```sh
sudo mkdir -p /mnt/iso
sudo mount -o loop ./path/to/SnowCrash.iso /mnt/iso
sudo ls /mnt/iso
```

You can clean it up later on using:
```sh
cd / # Or any other destination outside of /mnt/iso.
sudo umount /mnt/iso
sudo rm -r /mnt/iso
```

### Useful information

This doesn't provide us any useful information outside of the fact that it the image is built based on an `ubuntu` image.

## Exercices

You can register to the exercices using `levelXX:levelXX` username/password combinations where XX is a number ranging in `[00;14]`.

It is recommended to use `ssh` and related tools if available such as (`scp`, `rsync`...).

It is also possible to use external programs but these should be setup through a VMs or docker images (`ghidra`...).

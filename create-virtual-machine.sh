#!/bin/bash
#
#!/bin/bash
#

imgpath=./disk-file/ubuntu-22.04.img
isopath=./images/ubuntu-22.04.3-desktop-amd64.iso
vmname=ubuntu22.04-guest

# rm -f $imgpath
# qemu-img create -f raw -o size=50G $imgpath
# qemu-system-x86_64  

sudo virt-install -n $vmname\
    --memory 8192\
    --vcpus 4\
    --cdrom $isopath\
    --os-variant ubuntu20.04\
    --disk $imgpath\
    --console pty,target_type=serial \
    --graphics vnc,port=5900,listen=0.0.0.0 \
    --video vga\
    --network bridge=br0

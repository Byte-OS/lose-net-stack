.PHONY: all run clean run-nvme

TARGET      := riscv64imac-unknown-none-elf
KERNEL_FILE := target/$(TARGET)/release/example
KERNEL_BIN	:= kernel-qemu
DEBUG_FILE  ?= $(KERNEL_FILE)
FWDPORT 	:= 6200

OBJDUMP     := rust-objdump --arch-name=riscv64
OBJCOPY     := rust-objcopy --binary-architecture=riscv64

all:
	@rm -f kernel-qemu
	cargo build --release
	cp $(KERNEL_FILE) kernel-qemu

run: all
	@qemu-system-riscv64 \
		-machine virt \
		-nographic \
		-kernel $(KERNEL_BIN) \
		-netdev user,id=net0,hostfwd=udp::$(FWDPORT)-:2000 -object filter-dump,id=net0,netdev=net0,file=packets.pcap \
		-device virtio-net-device,netdev=net0

ping: 
	python3 ping.py $(FWDPORT)

server:
	python3 server.py $(FWDPORT)

.PHONY: all run ping server
.PHONY: all hello-world

all: hello-world

hello-world:
	git submodule update --init kvm-hello-world
	cd kvm-hello-world && patch -p1 < ../patch && cd -
	$(MAKE) -C kvm-hello-world kvm-hello-world

clean:
	$(MAKE) -C kvm-hello-world clean
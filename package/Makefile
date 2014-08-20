#Makefile for SHIPS
package=$(shell grep Package control | cut -f2 -d" ")
version=$(shell grep Version control | cut -f2 -d" ")
arch=$(shell grep Architecture control | cut -f2 -d" ")

default: 
	cp -apr ../usr ../etc .
	tar -czf data.tar.gz usr etc
	tar -czf control.tar.gz control conffiles
	tar -czf ${package}-${version}_${arch}.ipk debian-binary data.tar.gz control.tar.gz
	rm data.tar.gz control.tar.gz
	exit 0

clean: 
	rm -rf usr etc 2>/dev/null || true
	rm data.tar.gz control.tar.gz *.ipk 2>/dev/null || true
	exit 0

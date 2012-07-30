name=argus-pdp
spec=fedora/$(name).spec
version=$(shell grep "Version:" $(spec) | sed -e "s/Version://g" -e "s/[ \t]*//g")
release=1
rpmbuild_dir=$(shell pwd)/rpmbuild
settings_file=src/main/build/emi-build-settings.xml
stage_dir=$(shell pwd)/stage

.PHONY: etics dist clean rpm

all: dist

clean:	
	rm -rf target $(rpmbuild_dir) stage tgz RPMS $(spec)

dist: prepare-spec
	mvn -B -s $(settings_file) package

prepare-spec:
	sed -e 's#@@BUILD_SETTINGS@@#$(settings_file)#g' $(spec).in > $(spec)

rpm: prepare-spec
	mkdir -p 	$(rpmbuild_dir)/BUILD $(rpmbuild_dir)/RPMS \
				$(rpmbuild_dir)/SOURCES $(rpmbuild_dir)/SPECS \
				$(rpmbuild_dir)/SRPMS
	
	cp target/$(name)-$(version).src.tar.gz $(rpmbuild_dir)/SOURCES/$(name)-$(version).tar.gz
	rpmbuild --nodeps -v -ba $(spec) --define "_topdir $(rpmbuild_dir)"

etics: dist rpm
	mkdir -p tgz RPMS
	cp target/*.tar.gz tgz
	cp -r $(rpmbuild_dir)/RPMS/* $(rpmbuild_dir)/SRPMS/* RPMS

stage:
	echo "Staging tarball in $(stage_dir)"
	mkdir -p $(stage_dir)
	tar -C $(stage_dir) -xvzf target/$(name)-$(version).tar.gz

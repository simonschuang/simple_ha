#
# Makefile for the library for LIBSLB.
#
#
#

Version := $(shell echo $(Version))
Release := $(shell echo $(Release))

ifeq (,${Version})
    Version := 1.4
endif
ifeq (,${Release})
    Release := 0
endif

export Version
export Release

RPMBUILD_FOLDER = /usr/src/redhat
TARFILES = *.c *.h Makefile
TARBALL = libslb-${Version}-${Release}.tar.gz

LIBSLB_SOURCES=daemon.c \
               libha.c \
               libslbipc.c \
               libsock-ipc.c \
               logger.c \
               signals.c \
               timerThread.c \
               libslb-netif.c \
               uiciname.c \
               librs_c_session.c \
               librs_IEL.c \
               librs_L2.c \
               librs_SLB.c \
               librs_Monitor.c \
               librs_security.c

LIBSLB_CFLAGS=\
	`pkg-config --cflags glib-2.0` \
	-I/usr/cloudos/common/include/rs/c

LIBSLB_LIBS=\
	`pkg-config --libs glib-2.0` \
	-Wl,-rpath,/usr/cloudos/common/lib/rs/ \
	-L/usr/cloudos/common/lib/rs -lccma_c_rs_api

LIBSLB_TEST_CFLAGS=`pkg-config --cflags glib-2.0 gthread-2.0`
LIBSLB_TEST_LIBS=`pkg-config --libs glib-2.0 gthread-2.0` ./libslb.so

all: 
	gcc -Wall -g -shared -o ./libslb.so $(LIBSLB_SOURCES) -fPIC -m64 $(LIBSLB_CFLAGS) $(LIBSLB_LIBS) || exit 1;
	gcc -Wall -g -D__LIBSOCK_IPC_SERVER__ -o libsock-ipc-server libsock-ipc-test.c $(LIBSLB_TEST_CFLAGS) $(LIBSLB_TEST_LIBS) || exit 1;
	gcc -Wall -g -D__LIBSOCK_IPC_CLIENT__ -o libsock-ipc-client libsock-ipc-test.c $(LIBSLB_TEST_CFLAGS) $(LIBSLB_TEST_LIBS) || exit 1;
	gcc -Wall -g -D__LIBHA_SERVER__ -o libha-server libha-test.c $(LIBSLB_TEST_CFLAGS) $(LIBSLB_TEST_LIBS) || exit 1;
	gcc -Wall -g -D__LIBHA_CLIENT__ -o libha-client libha-test.c $(LIBSLB_TEST_CFLAGS) $(LIBSLB_TEST_LIBS) || exit 1;
	gcc -Wall -g -DLIBSLBIPC_TEST -o test_slbipc libslbipc.c $(LIBSLB_TEST_CFLAGS) $(LIBSLB_TEST_LIBS) || exit 1;

	@echo ""
	@echo "Make complete"

clean:
	rm -rf libslb.so
	rm -rf libsock-ipc-server
	rm -rf libsock-ipc-client
	rm -rf libha-server
	rm -rf libha-client
	rm -rf test_slbipc

install: all
	mkdir -p $(BUILD_ROOT)/usr/cloudos/slb/lib/
	cp -rf libslb.so $(BUILD_ROOT)/usr/cloudos/slb/lib/
	mkdir -p $(BUILD_ROOT)/usr/cloudos/slb/include
	cp -rf libsock-ipc.h $(BUILD_ROOT)/usr/cloudos/slb/include
	cp -rf libha.h $(BUILD_ROOT)/usr/cloudos/slb/include
	cp -rf logger.h $(BUILD_ROOT)/usr/cloudos/slb/include
	cp -rf signals.h $(BUILD_ROOT)/usr/cloudos/slb/include
	cp -rf daemon.h $(BUILD_ROOT)/usr/cloudos/slb/include
	cp -rf list.h $(BUILD_ROOT)/usr/cloudos/slb/include
	cp -rf libslbipc.h $(BUILD_ROOT)/usr/cloudos/slb/include
	cp -rf slb_communicator_message_type.h $(BUILD_ROOT)/usr/cloudos/slb/include
	cp -rf timerThread.h $(BUILD_ROOT)/usr/cloudos/slb/include
	cp -rf libslb-netif.h $(BUILD_ROOT)/usr/cloudos/slb/include
	cp -rf uiciname.h $(BUILD_ROOT)/usr/cloudos/slb/include
	cp -rf librs_c_session.h $(BUILD_ROOT)/usr/cloudos/slb/include
	cp -rf librs_IEL.h $(BUILD_ROOT)/usr/cloudos/slb/include
	cp -rf librs_L2.h $(BUILD_ROOT)/usr/cloudos/slb/include
	cp -rf librs_SLB.h $(BUILD_ROOT)/usr/cloudos/slb/include
	cp -rf librs_Monitor.h $(BUILD_ROOT)/usr/cloudos/slb/include
	cp -rf librs_security.h $(BUILD_ROOT)/usr/cloudos/slb/include

uninstall:
	rm -rf $(BUILD_ROOT)/usr/cloudos/slb/lib/libslb.so
	rm -rf $(BUILD_ROOT)/usr/cloudos/slb/include/libsock-ipc.h
	rm -rf $(BUILD_ROOT)/usr/cloudos/slb/include/libha.h
	rm -rf $(BUILD_ROOT)/usr/cloudos/slb/include/logger.h
	rm -rf $(BUILD_ROOT)/usr/cloudos/slb/include/signals.h
	rm -rf $(BUILD_ROOT)/usr/cloudos/slb/include/daemon.h
	rm -rf $(BUILD_ROOT)/usr/cloudos/slb/include/list.h
	rm -rf $(BUILD_ROOT)/usr/cloudos/slb/include/libslbipc.h
	rm -rf $(BUILD_ROOT)/usr/cloudos/slb/include/slb_communicator_message_type.h
	rm -rf $(BUILD_ROOT)/usr/cloudos/slb/include/timerThread.h
	rm -rf $(BUILD_ROOT)/usr/cloudos/slb/include/libslb-netif.h
	rm -rf $(BUILD_ROOT)/usr/cloudos/slb/include/uiciname.h
	rm -rf $(BUILD_ROOT)/usr/cloudos/slb/include/librs_c_session.h
	rm -rf $(BUILD_ROOT)/usr/cloudos/slb/include/librs_IEL.h
	rm -rf $(BUILD_ROOT)/usr/cloudos/slb/include/librs_L2.h
	rm -rf $(BUILD_ROOT)/usr/cloudos/slb/include/librs_SLB.h
	rm -rf $(BUILD_ROOT)/usr/cloudos/slb/include/librs_Monitor.h
	rm -rf $(BUILD_ROOT)/usr/cloudos/slb/include/librs_security.h
	rmdir --ignore-fail-on-non-empty $(BUILD_ROOT)/usr/cloudos/slb/lib 
	rmdir --ignore-fail-on-non-empty $(BUILD_ROOT)/usr/cloudos/slb/include 
	rmdir --ignore-fail-on-non-empty $(BUILD_ROOT)/usr/cloudos/slb
	rmdir --ignore-fail-on-non-empty $(BUILD_ROOT)/usr/cloudos/

tarball: clean
	mkdir -p libslb-${Version}
	cp -a $(TARFILES) libslb-${Version}
	tar -zcf $(TARBALL) libslb-${Version}
	rm -rf libslb-${Version}

rpm: tarball
	mkdir -p $(RPMBUILD_FOLDER)/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
	mv -f $(TARBALL) $(RPMBUILD_FOLDER)/SOURCES/
	cp -rf libslb.spec $(RPMBUILD_FOLDER)/SPECS/
	rpmbuild -bb --define '_topdir $(RPMBUILD_FOLDER)/' $(RPMBUILD_FOLDER)/SPECS/libslb.spec
	mkdir -p ../../../packages/
	cp $(RPMBUILD_FOLDER)/RPMS/x86_64/libslb-${Version}-${Release}.x86_64.rpm ../../../packages/

deb: clean
	make -C ubuntu deb

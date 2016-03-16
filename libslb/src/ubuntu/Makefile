LIBSLB_SOURCES=../daemon.c \
               ../libha.c \
               ../libslbipc.c \
               ../libsock-ipc.c \
               ../logger.c \
               ../signals.c \
               ../timerThread.c \
               ../libslb-netif.c \
               ../uiciname.c \

LIBSLB_CFLAGS=`pkg-config --cflags glib-2.0`
LIBSLB_LIBS=`pkg-config --libs glib-2.0`

LIBSLB_TEST_CFLAGS=`pkg-config --cflags glib-2.0 gthread-2.0`
LIBSLB_TEST_LIBS=`pkg-config --libs glib-2.0 gthread-2.0` ../libslb.so

all:
	gcc -Wall -g -shared -o ../libslb.so $(LIBSLB_SOURCES) -fPIC -m64 $(LIBSLB_CFLAGS) $(LIBSLB_LIBS) || exit 1;
	gcc -Wall -g -D__LIBSOCK_IPC_SERVER__ -o ../libsock-ipc-server ../libsock-ipc-test.c $(LIBSLB_TEST_CFLAGS) $(LIBSLB_TEST_LIBS) || exit 1;
	gcc -Wall -g -D__LIBSOCK_IPC_CLIENT__ -o ../libsock-ipc-client ../libsock-ipc-test.c $(LIBSLB_TEST_CFLAGS) $(LIBSLB_TEST_LIBS) || exit 1;
	gcc -Wall -g -D__LIBHA_SERVER__ -o ../libha-server ../libha-test.c $(LIBSLB_TEST_CFLAGS) $(LIBSLB_TEST_LIBS) || exit 1;
	gcc -Wall -g -D__LIBHA_CLIENT__ -o ../libha-client ../libha-test.c $(LIBSLB_TEST_CFLAGS) $(LIBSLB_TEST_LIBS) || exit 1;
	gcc -Wall -g -DLIBSLBIPC_TEST -o ../test_slbipc ../libslbipc.c $(LIBSLB_TEST_CFLAGS) $(LIBSLB_TEST_LIBS) || exit 1;

	@echo ""
	@echo "Make complete"

clean:
	rm -rf ../libslb.so
	rm -rf ../libsock-ipc-server
	rm -rf ../libsock-ipc-client
	rm -rf ../libha-server
	rm -rf ../libha-client
	rm -rf ../test_slbipc

install:
	mkdir -p $(BUILD_ROOT)/usr/cloudos/slb/lib/
	cp -rf ../libslb.so $(BUILD_ROOT)/usr/cloudos/slb/lib/
	mkdir -p $(BUILD_ROOT)/usr/cloudos/slb/include
	cp -rf ../libsock-ipc.h $(BUILD_ROOT)/usr/cloudos/slb/include
	cp -rf ../libha.h $(BUILD_ROOT)/usr/cloudos/slb/include
	cp -rf ../logger.h $(BUILD_ROOT)/usr/cloudos/slb/include
	cp -rf ../signals.h $(BUILD_ROOT)/usr/cloudos/slb/include
	cp -rf ../daemon.h $(BUILD_ROOT)/usr/cloudos/slb/include
	cp -rf ../list.h $(BUILD_ROOT)/usr/cloudos/slb/include
	cp -rf ../libslbipc.h $(BUILD_ROOT)/usr/cloudos/slb/include
	cp -rf ../slb_communicator_message_type.h $(BUILD_ROOT)/usr/cloudos/slb/include
	cp -rf ../timerThread.h $(BUILD_ROOT)/usr/cloudos/slb/include
	cp -rf ../libslb-netif.h $(BUILD_ROOT)/usr/cloudos/slb/include
	cp -rf ../uiciname.h $(BUILD_ROOT)/usr/cloudos/slb/include

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

deb: clean
	bash build-libslb-deb.sh

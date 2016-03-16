#
# Makefile for the HA agent
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


TARFILES = *.c *.h ha-agent.init ha-agent.spec Makefile
TARBALL = ha-agent-${Version}-${Release}.tar.gz

EXEC = ha-agent
CC=gcc
CFLAGS=-g -Wall
LIBS=-lpthread -Wl,-rpath,/usr/cloudos/slb/lib -L/usr/cloudos/slb/lib -lslb `pkg-config --libs glib-2.0`
INCLUDES=-I. -I/usr/cloudos/slb/include `pkg-config --cflags glib-2.0`

COMPILE = $(CC) $(INCLUDES) $(CFLAGS) 
OBJS    = ha-agent.o main.o interface.o pidfile.o sockets.o
SOURCES = $(OBJS:.o=.c)

prefix  = usr/cloudos/slb
sbindir = $(BUILD_ROOT)/${prefix}/sbin
init_dir    = $(BUILD_ROOT)/etc/rc.d/init.d

.c.o:
	$(COMPILE) -c $<

all: $(OBJS)
	$(CC) $(INCLUDES) $(CFLAGS) $(LIBS) -o ha-agent *.[oa] || exit 1;
	@echo ""
	@echo "Make complete"

clean:
	rm -rf *.o
	rm -rf ha-agent
	@echo ""
	@echo "Make complete"

distclean:
	@set -e; \
	$(MAKE) distclean; done

uninstall:
	rm -f $(sbindir)/$(EXEC)
	rm -f $(init_dir)/ha-agent

install: all
	install -d $(sbindir)
	install -m 700 $(EXEC) $(sbindir)/$(EXEC)
	install -d $(init_dir)
	install -m 755 ha-agent.init $(init_dir)/ha-agent

tarball: clean
	mkdir -p ha-agent-${Version}
	cp -a $(TARFILES) ha-agent-${Version}
	tar -zcf $(TARBALL) ha-agent-${Version}
	rm -rf ha-agent-${Version}

rpm: tarball
	mv -f $(TARBALL) /usr/src/redhat/SOURCES/
	cp -rf ha-agent.spec /usr/src/redhat/SPECS/
	rpmbuild -bb --define '_topdir /usr/src/redhat/' /usr/src/redhat/SPECS/ha-agent.spec
	mkdir -p ../../../packages/
	cp /usr/src/redhat/RPMS/x86_64/ha-agent-${Version}-${Release}.x86_64.rpm ../../../packages/


CC?=gcc
CFLAGS+=-O2

PREFIX=/opt/stdio_sb
BINDIR=$(PREFIX)/bin

SRCS := stdio_sb.c
DEPDIR := .deps
DEPS := $(SRCS:%.c=$(DEPDIR)/%.d)

all: stdio_sb

$(DEPDIR)/%.d: $(DEPDIR)

$(DEPDIR):
	mkdir -p "$@"

%.o $(DEPDIR)/%.d: %.c $(DEPDIR)
	$(CC) -c $(CFLAGS) -MT "$*.o" -MP -MD -MF $(DEPDIR)/$*.d -o "$*.o" $<

stdio_sb: stdio_sb.o
	$(CC) -o "$@" $<
	

setcap:
	setcap cap_sys_admin,cap_sys_chroot+ep stdio_sb

install: stdio_sb
	install -m 0755 -Dt $(BINDIR) $<
	setcap cap_sys_admin,cap_sys_chroot+ep $(BINDIR)/stdio_sb
	

clean:
	rm -rf stdio_sb.o stdio_sb a.out $(DEPDIR)

-include $(DEPS)

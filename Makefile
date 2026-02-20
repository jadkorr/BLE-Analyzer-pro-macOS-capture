CC      ?= gcc
CFLAGS  := -O2 -Wall -Wextra -std=c11 \
           $(shell pkg-config --cflags libusb-1.0)
LDFLAGS := $(shell pkg-config --libs libusb-1.0)

TARGET  := wch_capture
SRCS    := wch_ble_analyzer.c wch_capture.c
OBJS    := $(SRCS:.c=.o)

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c wch_ble_analyzer.h
	$(CC) $(CFLAGS) -c -o $@ $<

install: $(TARGET)
	install -Dm755 $(TARGET)          $(DESTDIR)/usr/local/bin/$(TARGET)
	install -Dm644 99-wch-ble-analyzer.rules \
	    $(DESTDIR)/etc/udev/rules.d/99-wch-ble-analyzer.rules
	@echo "Run: sudo udevadm control --reload-rules && sudo udevadm trigger"

clean:
	rm -f $(OBJS) $(TARGET)

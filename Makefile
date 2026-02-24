CC      ?= gcc
CFLAGS  := -O2 -Wall -Wextra -std=c11 \
           $(shell pkg-config --cflags libusb-1.0 2>/dev/null)
LDFLAGS := $(shell pkg-config --libs libusb-1.0 2>/dev/null)

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
	install -m 755 $(TARGET) $(DESTDIR)/usr/local/bin/$(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)

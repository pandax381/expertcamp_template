APPS = 

TEST = test/step1.exe \
       test/step2.exe \
       test/step3.exe \
       test/step4.exe \
       test/step5.exe \
       test/step6.exe \
       test/step7.exe \
       test/step8.exe \

DRIVERS = driver/null.o \
          driver/loopback.o \

OBJS = util.o \
       net.o \
       ip.o \
       icmp.o \

CFLAGS := $(CFLAGS) -g -W -Wall -Wno-unused-parameter -I .

ifeq ($(shell uname),Linux)
       CFLAGS := $(CFLAGS) -pthread
       TEST := $(TEST)
       DRIVERS := $(DRIVERS)
endif

.SUFFIXES:
.SUFFIXES: .c .o

.PHONY: all clean

all: $(APPS) $(TEST)

$(APPS): % : %.o $(OBJS) $(DRIVERS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(TEST): %.exe : %.o $(OBJS) $(DRIVERS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(APPS) $(APPS:=.o) $(OBJS) $(DRIVERS) $(TEST) $(TEST:.exe=.o)

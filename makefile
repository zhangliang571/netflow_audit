#
# makefile for netflow_audit unit test
# build a exec file
#


CC:=g++
INCLUDE:=./
LIBS:= -lpthread -lpcap -lboost_date_time
BIN:=netflow_audit
SRCS:=$(wildcard *.c++)
OBJS:=$(patsubst %.c++, %.o, $(SRCS))

.PHONY: all clean
all: $(BIN)

$(BIN):$(OBJS)
	$(CC) -Wall -g $(OBJS) $(LIBS) -o $(BIN) 

%.o:%.c++
	$(CC) -I $(INCLUDE) -o $@ -c $<
	
clean:
	rm -f $(BIN)  *.o 


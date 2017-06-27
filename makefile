#
# makefile for netflow_audit unit test
# build a exec file
#


CC:=g++
INCLUDE:=./
FLAGS:= -g 
DFLAGS:= -DDEBUG
LIBS:= -lpthread -lpcap -lboost_date_time -lboost_regex -L /usr/local/lib
BIN:=netflow_audit
SRCS:=$(wildcard *.c++)
OBJS:=$(patsubst %.c++, %.o, $(SRCS))

.PHONY: all clean
all: $(BIN)

$(BIN):$(OBJS)
	$(CC) -Wall $(FLAGS) $(OBJS) $(LIBS) -o $(BIN) 

%.o:%.c++
	$(CC) -I $(INCLUDE) $(FLAGS) -o $@ -c $<
	
clean:
	rm -f $(BIN)  *.o 


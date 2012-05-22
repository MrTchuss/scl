PRG = bin/scl

SRCS = main.c \
       sc.c \
       scutils.c \
       args.c

OBJS = $(SRCS:.c=.o)
DEPS = $(SRCS:.c=.d)

LIBDIR = 

LIBS = 

C = /usr/bin/gcc

C_FLAGS = -g -Wall

C_INCLUDES = -I include

%.o: src/%.c
	$(C) $(C_FLAGS) $(C_INCLUDES) -c -o $@ $<

%.d: src/%.c
	@rm -f $@; \
	$(C) -MM $(C_FLAGS) $(C_INCLUDES) $< > $@.tmp; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.tmp > $@; \
	rm $@.tmp

$(PRG): $(OBJS)
	$(C) $(C_FLAGS) $(C_INCLUDES) $(LIBDIR) -o $(PRG) $(OBJS) $(LIBS)


all: $(PRG)
clean:
	rm $(PRG) $(OBJS) $(DEPS)

ifneq ($(strip $(DEPS)),)
-include $(DEPS)
endif

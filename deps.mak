.include "vars.mak"

.depend:
	$(CC) $(INC) -MM $(SRCS) > $(.TARGET)



PREFIX       = /usr/local
INSTALL_PATH = $(PREFIX)/include
NAME = bpf

def:
	@echo "Hello. This is bpf"

install:
	@echo install to $(INSTALL_PATH)...
	@cp -rf $(NAME) $(INSTALL_PATH)
	@echo install to $(INSTALL_PATH)... OK

uninstall:
	@echo uninstall to rm "$(INSTALL_PATH)/$(NAME)"...
	@rm -rf $(INSTALL_PATH)/$(NAME)
	@echo uninstall to rm "$(INSTALL_PATH)/$(NAME)"... OK

# Makefile - Monitor de Tráfego de Rede (raw sockets)
#
#   make          -> compila o monitor
#   make run      -> executa (precisa de sudo e do nome da interface; use IFACE=)
#   make clean    -> remove binário e CSVs gerados
#
# -std=gnu11 já ativa _DEFAULT_SOURCE; mantemos o -D explícito para o build
# funcionar também caso alguém troque para -std=c11.

CC     := gcc
CFLAGS := -std=gnu11 -D_DEFAULT_SOURCE -Wall -Wextra -O2
BIN    := monitor

.PHONY: all clean run

all: $(BIN)

$(BIN): monitor.c
	$(CC) $(CFLAGS) $< -o $@

# O raw socket AF_PACKET exige root (ou CAP_NET_RAW). Ex.: make run IFACE=tun0
IFACE ?= tun0
run: $(BIN)
	sudo ./$(BIN) $(IFACE)

clean:
	rm -f $(BIN) *.o camada_internet.csv camada_transporte.csv camada_aplicacao.csv
